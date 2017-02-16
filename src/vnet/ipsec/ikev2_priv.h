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

#include <vnet/ipsec/ikev2.h>

#include <vppinfra/hash.h>
#include <vppinfra/elog.h>
#include <vppinfra/error.h>

#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define IKEV2_DEBUG_PAYLOAD 1

#if IKEV2_DEBUG_PAYLOAD == 1
#define DBG_PLD(my_args...) clib_warning(my_args)
#else
#define DBG_PLD(my_args...)
#endif

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
  u8 ts_type;
  u8 protocol_id;
  u16 selector_len;
  u16 start_port;
  u16 end_port;
  ip4_address_t start_addr;
  ip4_address_t end_addr;
} ikev2_ts_t;

typedef struct
{
  u32 sw_if_index;
  ip4_address_t ip4;
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
  u8 is_enabled;

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
} ikev2_profile_t;

typedef struct
{
  ikev2_state_t state;
  u8 unsupported_cp;
  u8 initial_contact;
  ip4_address_t iaddr;
  ip4_address_t raddr;
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
  ikev2_profile_t *profile;

  ikev2_child_sa_t *childs;
} ikev2_sa_t;


typedef struct
{
  /* pool of IKEv2 Security Associations */
  ikev2_sa_t *sas;

  /* hash */
  uword *sa_by_rspi;
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

} ikev2_main_t;

ikev2_main_t ikev2_main;

void ikev2_sa_free_proposal_vector (ikev2_sa_proposal_t ** v);
ikev2_sa_transform_t *ikev2_sa_get_td_for_type (ikev2_sa_proposal_t * p,
						ikev2_transform_type_t type);

/* ikev2_crypto.c */
v8 *ikev2_calc_prf (ikev2_sa_transform_t * tr, v8 * key, v8 * data);
u8 *ikev2_calc_prfplus (ikev2_sa_transform_t * tr, u8 * key, u8 * seed,
			int len);
v8 *ikev2_calc_integr (ikev2_sa_transform_t * tr, v8 * key, u8 * data,
		       int len);
v8 *ikev2_decrypt_data (ikev2_sa_t * sa, u8 * data, int len);
int ikev2_encrypt_data (ikev2_sa_t * sa, v8 * src, u8 * dst);
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
ikev2_sa_proposal_t *ikev2_parse_sa_payload (ike_payload_header_t * ikep);
ikev2_ts_t *ikev2_parse_ts_payload (ike_payload_header_t * ikep);
ikev2_delete_t *ikev2_parse_delete_payload (ike_payload_header_t * ikep);
ikev2_notify_t *ikev2_parse_notify_payload (ike_payload_header_t * ikep);

#endif /* __included_ikev2_priv_h__ */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
