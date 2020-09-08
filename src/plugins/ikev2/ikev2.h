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
#ifndef __included_ikev2_h__
#define __included_ikev2_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#include <vppinfra/error.h>

#define IKEV2_NONCE_SIZE  32
#define IKEV2_PORT        500
#define IKEV2_PORT_NATT   4500
#define IKEV2_KEY_PAD "Key Pad for IKEv2"

#define IKEV2_GCM_ICV_SIZE 16
#define IKEV2_GCM_NONCE_SIZE 12
#define IKEV2_GCM_SALT_SIZE 4
#define IKEV2_GCM_IV_SIZE (IKEV2_GCM_NONCE_SIZE - IKEV2_GCM_SALT_SIZE)

typedef u8 v8;

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u64 ispi;
  u64 rspi;
  u8 nextpayload;
  u8 version;
  u8 exchange;
  u8 flags;
  u32 msgid; u32 length; u8 payload[0];
}) ike_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 nextpayload;
  u8 flags;
  u16 length;
  u16 dh_group;
  u8 reserved[2];
  u8 payload[0];
}) ike_ke_payload_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 nextpayload;
  u8 flags;
  u16 length; u8 payload[0];
}) ike_payload_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 nextpayload;
  u8 flags;
  u16 length;
  u8 auth_method;
  u8 reserved[3];
  u8 payload[0];
}) ike_auth_payload_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 nextpayload;
  u8 flags;
  u16 length;
  u8 id_type;
  u8 reserved[3]; u8 payload[0];
}) ike_id_payload_header_t;
/* *INDENT-ON* */

#define IKE_VERSION_2                    0x20

#define IKEV2_EXCHANGE_SA_INIT           34
#define IKEV2_EXCHANGE_IKE_AUTH          35
#define IKEV2_EXCHANGE_CREATE_CHILD_SA   36
#define IKEV2_EXCHANGE_INFORMATIONAL     37

#define IKEV2_HDR_FLAG_INITIATOR         (1<<3)
#define IKEV2_HDR_FLAG_VERSION           (1<<4)
#define IKEV2_HDR_FLAG_RESPONSE          (1<<5)

#define IKEV2_PAYLOAD_FLAG_CRITICAL      (1<<7)

#define IKEV2_PAYLOAD_NONE      0
#define IKEV2_PAYLOAD_NAT_D     20
#define IKEV2_PAYLOAD_NAT_OA    21
#define IKEV2_PAYLOAD_SA        33
#define IKEV2_PAYLOAD_KE        34
#define IKEV2_PAYLOAD_IDI       35
#define IKEV2_PAYLOAD_IDR       36
#define IKEV2_PAYLOAD_AUTH      39
#define IKEV2_PAYLOAD_NONCE     40
#define IKEV2_PAYLOAD_NOTIFY    41
#define IKEV2_PAYLOAD_DELETE    42
#define IKEV2_PAYLOAD_VENDOR    43
#define IKEV2_PAYLOAD_TSI       44
#define IKEV2_PAYLOAD_TSR       45
#define IKEV2_PAYLOAD_SK        46

typedef enum
{
  IKEV2_PROTOCOL_IKE = 1,
  IKEV2_PROTOCOL_AH = 2,
  IKEV2_PROTOCOL_ESP = 3,
} ikev2_protocol_id_t;

#define foreach_ikev2_notify_msg_type \
  _(    0, NONE)                                \
  _(    1, UNSUPPORTED_CRITICAL_PAYLOAD)        \
  _(    4, INVALID_IKE_SPI)                     \
  _(    5, INVALID_MAJOR_VERSION)               \
  _(    7, INVALID_SYNTAX)                      \
  _(    8, INVALID_MESSAGE_ID)                  \
  _(   11, INVALID_SPI)                         \
  _(   14, NO_PROPOSAL_CHOSEN)                  \
  _(   17, INVALID_KE_PAYLOAD)                  \
  _(   24, AUTHENTICATION_FAILED)               \
  _(   34, SINGLE_PAIR_REQUIRED)                \
  _(   35, NO_ADDITIONAL_SAS)                   \
  _(   36, INTERNAL_ADDRESS_FAILURE)            \
  _(   37, FAILED_CP_REQUIRED)                  \
  _(   38, TS_UNACCEPTABLE)                     \
  _(   39, INVALID_SELECTORS)                   \
  _(   40, UNACCEPTABLE_ADDRESSES)              \
  _(   41, UNEXPECTED_NAT_DETECTED)             \
  _(   42, USE_ASSIGNED_HoA)                    \
  _(   43, TEMPORARY_FAILURE)                   \
  _(   44, CHILD_SA_NOT_FOUND)                  \
  _(   45, INVALID_GROUP_ID)                    \
  _(   46, AUTHORIZATION_FAILED)                \
  _(16384, INITIAL_CONTACT)                     \
  _(16385, SET_WINDOW_SIZE)                     \
  _(16386, ADDITIONAL_TS_POSSIBLE)              \
  _(16387, IPCOMP_SUPPORTED)                    \
  _(16388, NAT_DETECTION_SOURCE_IP)             \
  _(16389, NAT_DETECTION_DESTINATION_IP)        \
  _(16390, COOKIE)                              \
  _(16391, USE_TRANSPORT_MODE)                  \
  _(16392, HTTP_CERT_LOOKUP_SUPPORTED)          \
  _(16393, REKEY_SA)                            \
  _(16394, ESP_TFC_PADDING_NOT_SUPPORTED)       \
  _(16395, NON_FIRST_FRAGMENTS_ALSO)            \
  _(16396, MOBIKE_SUPPORTED)                    \
  _(16397, ADDITIONAL_IP4_ADDRESS)              \
  _(16398, ADDITIONAL_IP6_ADDRESS)              \
  _(16399, NO_ADDITIONAL_ADDRESSES)             \
  _(16400, UPDATE_SA_ADDRESSES)                 \
  _(16401, COOKIE2)                             \
  _(16402, NO_NATS_ALLOWED)                     \
  _(16403, AUTH_LIFETIME)                       \
  _(16404, MULTIPLE_AUTH_SUPPORTED)             \
  _(16405, ANOTHER_AUTH_FOLLOWS)                \
  _(16406, REDIRECT_SUPPORTED)                  \
  _(16407, REDIRECT)                            \
  _(16408, REDIRECTED_FROM)                     \
  _(16409, TICKET_LT_OPAQUE)                    \
  _(16410, TICKET_REQUEST)                      \
  _(16411, TICKET_ACK)                          \
  _(16412, TICKET_NACK)                         \
  _(16413, TICKET_OPAQUE)                       \
  _(16414, LINK_ID)                             \
  _(16415, USE_WESP_MODE)                       \
  _(16416, ROHC_SUPPORTED)                      \
  _(16417, EAP_ONLY_AUTHENTICATION)             \
  _(16418, CHILDLESS_IKEV2_SUPPORTED)           \
  _(16419, QUICK_CRASH_DETECTION)               \
  _(16420, IKEV2_MESSAGE_ID_SYNC_SUPPORTED)     \
  _(16421, IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED) \
  _(16422, IKEV2_MESSAGE_ID_SYNC)               \
  _(16423, IPSEC_REPLAY_COUNTER_SYNC)           \
  _(16424, SECURE_PASSWORD_METHODS)             \
  _(16425, PSK_PERSIST)                         \
  _(16426, PSK_CONFIRM)                         \
  _(16427, ERX_SUPPORTED)                       \
  _(16428, IFOM_CAPABILITY)                     \
  _(16429, SENDER_REQUEST_ID)                   \
  _(16430, IKEV2_FRAGMENTATION_SUPPORTED)       \
  _(16431, SIGNATURE_HASH_ALGORITHMS)


typedef enum
{
#define _(v,f) IKEV2_NOTIFY_MSG_##f = v,
  foreach_ikev2_notify_msg_type
#undef _
} ikev2_notify_msg_type_t;

#define foreach_ikev2_transform_type       \
  _(0, UNDEFINED, "undefined") \
  _(1, ENCR,  "encr")           \
  _(2, PRF,   "prf")            \
  _(3, INTEG, "integ")          \
  _(4, DH,    "dh-group")       \
  _(5, ESN,   "esn")

typedef enum
{
#define _(v,f,s) IKEV2_TRANSFORM_TYPE_##f = v,
  foreach_ikev2_transform_type
#undef _
  IKEV2_TRANSFORM_NUM_TYPES
} ikev2_transform_type_t;


#define foreach_ikev2_transform_encr_type     \
  _(1 , DES_IV64,  "des-iv64") \
  _(2 , DES,       "des")      \
  _(3 , 3DES,      "3des")     \
  _(4 , RC5,       "rc5")      \
  _(5 , IDEA,      "idea")     \
  _(6 , CAST,      "cast")     \
  _(7 , BLOWFISH,  "blowfish") \
  _(8 , 3IDEA,     "3idea")    \
  _(9 , DES_IV32,  "des-iv32") \
  _(11, NULL,      "null")     \
  _(12, AES_CBC,   "aes-cbc")  \
  _(13, AES_CTR,   "aes-ctr")  \
  _(20, AES_GCM_16, "aes-gcm-16")

typedef enum
{
#define _(v,f,str) IKEV2_TRANSFORM_ENCR_TYPE_##f = v,
  foreach_ikev2_transform_encr_type
#undef _
} ikev2_transform_encr_type_t;

#define foreach_ikev2_transform_prf_type   \
  _(1, PRF_HMAC_MD5,      "hmac-md5")      \
  _(2, PRF_HMAC_SHA1,     "hmac-sha1")     \
  _(3, PRF_MAC_TIGER,     "mac-tiger")     \
  _(4, PRF_AES128_XCBC,   "aes128-xcbc")   \
  _(5, PRF_HMAC_SHA2_256, "hmac-sha2-256") \
  _(6, PRF_HMAC_SHA2_384, "hmac-sha2-384") \
  _(7, PRF_HMAC_SHA2_512, "hmac-sha2-512") \
  _(8, PRF_AES128_CMAC,   "aes128-cmac")

typedef enum
{
#define _(v,f,str) IKEV2_TRANSFORM_PRF_TYPE_##f = v,
  foreach_ikev2_transform_prf_type
#undef _
} ikev2_transform_prf_type_t;

#define foreach_ikev2_transform_integ_type           \
  _(0,  NONE,                   "none")              \
  _(1,  AUTH_HMAC_MD5_96,       "md5-96")            \
  _(2,  AUTH_HMAC_SHA1_96,      "sha1-96")           \
  _(3,  AUTH_DES_MAC,           "des-mac")           \
  _(4,  AUTH_KPDK_MD5,          "kpdk-md5")          \
  _(5,  AUTH_AES_XCBC_96,       "aes-xcbc-96")       \
  _(6,  AUTH_HMAC_MD5_128,      "md5-128")           \
  _(7,  AUTH_HMAC_SHA1_160,     "sha1-160")          \
  _(8,  AUTH_AES_CMAC_96,       "cmac-96")           \
  _(9,  AUTH_AES_128_GMAC,      "aes-128-gmac")      \
  _(10, AUTH_AES_192_GMAC,      "aes-192-gmac")      \
  _(11, AUTH_AES_256_GMAC,      "aes-256-gmac")      \
  _(12, AUTH_HMAC_SHA2_256_128, "hmac-sha2-256-128") \
  _(13, AUTH_HMAC_SHA2_384_192, "hmac-sha2-384-192") \
  _(14, AUTH_HMAC_SHA2_512_256, "hmac-sha2-512-256")

typedef enum
{
#define _(v,f, str) IKEV2_TRANSFORM_INTEG_TYPE_##f = v,
  foreach_ikev2_transform_integ_type
#undef _
} ikev2_transform_integ_type_t;

#if defined(OPENSSL_NO_CISCO_FECDH)
#define foreach_ikev2_transform_dh_type \
  _(0, NONE,           "none")          \
  _(1, MODP_768,       "modp-768")      \
  _(2, MODP_1024,      "modp-1024")     \
  _(5, MODP_1536,      "modp-1536")     \
  _(14, MODP_2048,     "modp-2048")     \
  _(15, MODP_3072,     "modp-3072")     \
  _(16, MODP_4096,     "modp-4096")     \
  _(17, MODP_6144,     "modp-6144")     \
  _(18, MODP_8192,     "modp-8192")     \
  _(19, ECP_256,       "ecp-256")       \
  _(20, ECP_384,       "ecp-384")       \
  _(21, ECP_521,       "ecp-521")       \
  _(22, MODP_1024_160, "modp-1024-160") \
  _(23, MODP_2048_224, "modp-2048-224") \
  _(24, MODP_2048_256, "modp-2048-256") \
  _(25, ECP_192,       "ecp-192")       \
  _(26, ECP_224,       "ecp-224")       \
  _(27, BRAINPOOL_224, "brainpool-224") \
  _(28, BRAINPOOL_256, "brainpool-256") \
  _(29, BRAINPOOL_384, "brainpool-384") \
  _(30, BRAINPOOL_512, "brainpool-512")
#else
#define foreach_ikev2_transform_dh_type \
  _(0, NONE,           "none")          \
  _(1, MODP_768,       "modp-768")      \
  _(2, MODP_1024,      "modp-1024")     \
  _(5, MODP_1536,      "modp-1536")     \
  _(14, MODP_2048,     "modp-2048")     \
  _(15, MODP_3072,     "modp-3072")     \
  _(16, MODP_4096,     "modp-4096")     \
  _(17, MODP_6144,     "modp-6144")     \
  _(18, MODP_8192,     "modp-8192")     \
  _(19, ECP_256,       "ecp-256")       \
  _(20, ECP_384,       "ecp-384")       \
  _(21, ECP_521,       "ecp-521")       \
  _(22, MODP_1024_160, "modp-1024-160") \
  _(23, MODP_2048_224, "modp-2048-224") \
  _(24, MODP_2048_256, "modp-2048-256") \
  _(25, ECP_192,       "ecp-192")
#endif

typedef enum
{
#define _(v,f, str) IKEV2_TRANSFORM_DH_TYPE_##f = v,
  foreach_ikev2_transform_dh_type
#undef _
} ikev2_transform_dh_type_t;

#define foreach_ikev2_transform_esn_type     \
  _(0, NO_ESN, "no")       \
  _(1, ESN,    "yes")

typedef enum
{
#define _(v,f,str) IKEV2_TRANSFORM_ESN_TYPE_##f = v,
  foreach_ikev2_transform_esn_type
#undef _
} ikev2_transform_esn_type_t;

#define foreach_ikev2_auth_method \
 _( 1, RSA_SIG,        "rsa-sig")        \
 _( 2, SHARED_KEY_MIC, "shared-key-mic")

typedef enum
{
#define _(v,f,s) IKEV2_AUTH_METHOD_##f = v,
  foreach_ikev2_auth_method
#undef _
} ikev2_auth_method_t;

#define foreach_ikev2_id_type \
 _( 1, ID_IPV4_ADDR,   "ip4-addr")    \
 _( 2, ID_FQDN,        "fqdn")        \
 _( 3, ID_RFC822_ADDR, "rfc822")      \
 _( 5, ID_IPV6_ADDR,   "ip6-addr")    \
 _( 9, ID_DER_ASN1_DN, "der-asn1-dn") \
 _(10, ID_DER_ASN1_GN, "der-asn1-gn") \
 _(11, ID_KEY_ID,      "key-id")

typedef enum
{
#define _(v,f,s) IKEV2_ID_TYPE_##f = v,
  foreach_ikev2_id_type
#undef _
} ikev2_id_type_t;

typedef enum
{
  TS_IPV4_ADDR_RANGE = 7,
  TS_IPV6_ADDR_RANGE = 8,
} ikev2_traffic_selector_type_t;

clib_error_t *ikev2_init (vlib_main_t * vm);
clib_error_t *ikev2_set_local_key (vlib_main_t * vm, u8 * file);
clib_error_t *ikev2_add_del_profile (vlib_main_t * vm, u8 * name, int is_add);
clib_error_t *ikev2_set_profile_auth (vlib_main_t * vm, u8 * name,
				      u8 auth_method, u8 * data,
				      u8 data_hex_format);
clib_error_t *ikev2_set_profile_id (vlib_main_t * vm, u8 * name,
				    u8 id_type, u8 * data, int is_local);
clib_error_t *ikev2_set_profile_ts (vlib_main_t * vm, u8 * name,
				    u8 protocol_id, u16 start_port,
				    u16 end_port, ip_address_t start_addr,
				    ip_address_t end_addr, int is_local);
clib_error_t *ikev2_set_profile_responder (vlib_main_t * vm, u8 * name,
					   u32 sw_if_index,
					   ip_address_t addr);
clib_error_t *ikev2_set_profile_ike_transforms (vlib_main_t * vm, u8 * name,
						ikev2_transform_encr_type_t
						crypto_alg,
						ikev2_transform_integ_type_t
						integ_alg,
						ikev2_transform_dh_type_t
						dh_type, u32 crypto_key_size);
clib_error_t *ikev2_set_profile_esp_transforms (vlib_main_t * vm, u8 * name,
						ikev2_transform_encr_type_t
						crypto_alg,
						ikev2_transform_integ_type_t
						integ_alg,
						u32 crypto_key_size);
clib_error_t *ikev2_set_profile_sa_lifetime (vlib_main_t * vm, u8 * name,
					     u64 lifetime, u32 jitter,
					     u32 handover, u64 maxdata);
clib_error_t *ikev2_set_profile_tunnel_interface (vlib_main_t * vm, u8 * name,
						  u32 sw_if_index);
vnet_api_error_t ikev2_set_profile_ipsec_udp_port (vlib_main_t * vm,
						   u8 * name, u16 port,
						   u8 is_set);
clib_error_t *ikev2_set_profile_udp_encap (vlib_main_t * vm, u8 * name);
clib_error_t *ikev2_initiate_sa_init (vlib_main_t * vm, u8 * name);
clib_error_t *ikev2_initiate_delete_child_sa (vlib_main_t * vm, u32 ispi);
clib_error_t *ikev2_initiate_delete_ike_sa (vlib_main_t * vm, u64 ispi);
clib_error_t *ikev2_initiate_rekey_child_sa (vlib_main_t * vm, u32 ispi);

/* ikev2_format.c */
u8 *format_ikev2_auth_method (u8 * s, va_list * args);
u8 *format_ikev2_id_type (u8 * s, va_list * args);
u8 *format_ikev2_transform_type (u8 * s, va_list * args);
u8 *format_ikev2_notify_msg_type (u8 * s, va_list * args);
u8 *format_ikev2_transform_encr_type (u8 * s, va_list * args);
u8 *format_ikev2_transform_prf_type (u8 * s, va_list * args);
u8 *format_ikev2_transform_integ_type (u8 * s, va_list * args);
u8 *format_ikev2_transform_dh_type (u8 * s, va_list * args);
u8 *format_ikev2_transform_esn_type (u8 * s, va_list * args);
u8 *format_ikev2_sa_transform (u8 * s, va_list * args);

uword unformat_ikev2_auth_method (unformat_input_t * input, va_list * args);
uword unformat_ikev2_id_type (unformat_input_t * input, va_list * args);
uword unformat_ikev2_transform_type (unformat_input_t * input,
				     va_list * args);
uword unformat_ikev2_transform_encr_type (unformat_input_t * input,
					  va_list * args);
uword unformat_ikev2_transform_prf_type (unformat_input_t * input,
					 va_list * args);
uword unformat_ikev2_transform_integ_type (unformat_input_t * input,
					   va_list * args);
uword unformat_ikev2_transform_dh_type (unformat_input_t * input,
					va_list * args);
uword unformat_ikev2_transform_esn_type (unformat_input_t * input,
					 va_list * args);
void ikev2_cli_reference (void);

clib_error_t *ikev2_set_liveness_params (u32 period, u32 max_retries);

#endif /* __included_ikev2_h__ */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
