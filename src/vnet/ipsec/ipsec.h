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
#ifndef __IPSEC_H__
#define __IPSEC_H__

#include <vnet/ip/ip.h>
#include <vnet/feature/feature.h>

#define IPSEC_FLAG_IPSEC_GRE_TUNNEL (1 << 0)


#define foreach_ipsec_output_next                \
_(DROP, "error-drop")                            \
_(ESP_ENCRYPT, "esp-encrypt")

#define _(v, s) IPSEC_OUTPUT_NEXT_##v,
typedef enum
{
  foreach_ipsec_output_next
#undef _
    IPSEC_OUTPUT_N_NEXT,
} ipsec_output_next_t;


#define foreach_ipsec_input_next                \
_(DROP, "error-drop")                           \
_(ESP_DECRYPT, "esp-decrypt")

#define _(v, s) IPSEC_INPUT_NEXT_##v,
typedef enum
{
  foreach_ipsec_input_next
#undef _
    IPSEC_INPUT_N_NEXT,
} ipsec_input_next_t;


#define foreach_ipsec_policy_action \
  _(0, BYPASS,  "bypass")          \
  _(1, DISCARD, "discard")         \
  _(2, RESOLVE, "resolve")         \
  _(3, PROTECT, "protect")

typedef enum
{
#define _(v,f,s) IPSEC_POLICY_ACTION_##f = v,
  foreach_ipsec_policy_action
#undef _
    IPSEC_POLICY_N_ACTION,
} ipsec_policy_action_t;

#define foreach_ipsec_crypto_alg \
  _(0, NONE,  "none")               \
  _(1, AES_CBC_128, "aes-cbc-128")  \
  _(2, AES_CBC_192, "aes-cbc-192")  \
  _(3, AES_CBC_256, "aes-cbc-256")  \
  _(4, AES_CTR_128, "aes-ctr-128")  \
  _(5, AES_CTR_192, "aes-ctr-192")  \
  _(6, AES_CTR_256, "aes-ctr-256")  \
  _(7, AES_GCM_128, "aes-gcm-128")  \
  _(8, AES_GCM_192, "aes-gcm-192")  \
  _(9, AES_GCM_256, "aes-gcm-256")

typedef enum
{
#define _(v,f,s) IPSEC_CRYPTO_ALG_##f = v,
  foreach_ipsec_crypto_alg
#undef _
    IPSEC_CRYPTO_N_ALG,
} ipsec_crypto_alg_t;

#define foreach_ipsec_integ_alg \
  _(0, NONE,  "none")                                                     \
  _(1, MD5_96, "md5-96")           /* RFC2403 */                          \
  _(2, SHA1_96, "sha1-96")         /* RFC2404 */                          \
  _(3, SHA_256_96, "sha-256-96")   /* draft-ietf-ipsec-ciph-sha-256-00 */ \
  _(4, SHA_256_128, "sha-256-128") /* RFC4868 */                          \
  _(5, SHA_384_192, "sha-384-192") /* RFC4868 */                          \
  _(6, SHA_512_256, "sha-512-256")	/* RFC4868 */

typedef enum
{
#define _(v,f,s) IPSEC_INTEG_ALG_##f = v,
  foreach_ipsec_integ_alg
#undef _
    IPSEC_INTEG_N_ALG,
} ipsec_integ_alg_t;

typedef enum
{
  IPSEC_PROTOCOL_AH = 0,
  IPSEC_PROTOCOL_ESP = 1
} ipsec_protocol_t;

typedef struct
{
  u32 id;
  u32 spi;
  ipsec_protocol_t protocol;

  ipsec_crypto_alg_t crypto_alg;
  u8 crypto_key_len;
  u8 crypto_key[128];

  ipsec_integ_alg_t integ_alg;
  u8 integ_key_len;
  u8 integ_key[128];

  u8 use_esn;
  u8 use_anti_replay;

  u8 is_tunnel;
  u8 is_tunnel_ip6;
  ip46_address_t tunnel_src_addr;
  ip46_address_t tunnel_dst_addr;

  u32 salt;

  /* runtime */
  u32 seq;
  u32 seq_hi;
  u32 last_seq;
  u32 last_seq_hi;
  u64 replay_window;

  /*lifetime data */
  u64 total_data_size;
} ipsec_sa_t;

typedef struct
{
  ip46_address_t start, stop;
} ip46_address_range_t;

typedef struct
{
  u16 start, stop;
} port_range_t;

typedef struct
{
  u8 is_add;
  u8 esn;
  u8 anti_replay;
  ip4_address_t local_ip, remote_ip;
  u32 local_spi;
  u32 remote_spi;
  ipsec_crypto_alg_t crypto_alg;
  u8 local_crypto_key_len;
  u8 local_crypto_key[128];
  u8 remote_crypto_key_len;
  u8 remote_crypto_key[128];
  ipsec_integ_alg_t integ_alg;
  u8 local_integ_key_len;
  u8 local_integ_key[128];
  u8 remote_integ_key_len;
  u8 remote_integ_key[128];
} ipsec_add_del_tunnel_args_t;

typedef struct
{
  u8 is_add;
  u32 local_sa_id;
  u32 remote_sa_id;
  ip4_address_t local_ip;
  ip4_address_t remote_ip;
} ipsec_add_del_ipsec_gre_tunnel_args_t;

typedef enum
{
  IPSEC_IF_SET_KEY_TYPE_NONE,
  IPSEC_IF_SET_KEY_TYPE_LOCAL_CRYPTO,
  IPSEC_IF_SET_KEY_TYPE_REMOTE_CRYPTO,
  IPSEC_IF_SET_KEY_TYPE_LOCAL_INTEG,
  IPSEC_IF_SET_KEY_TYPE_REMOTE_INTEG,
} ipsec_if_set_key_type_t;

typedef struct
{
  u32 id;
  i32 priority;
  u8 is_outbound;

  // Selector
  u8 is_ipv6;
  ip46_address_range_t laddr;
  ip46_address_range_t raddr;
  u8 protocol;
  port_range_t lport;
  port_range_t rport;

  // Policy
  u8 policy;
  u32 sa_id;
  u32 sa_index;

  // Counter
  vlib_counter_t counter;
} ipsec_policy_t;

typedef struct
{
  u32 id;
  /* pool of policies */
  ipsec_policy_t *policies;
  /* vectors of policy indices */
  u32 *ipv4_outbound_policies;
  u32 *ipv6_outbound_policies;
  u32 *ipv4_inbound_protect_policy_indices;
  u32 *ipv4_inbound_policy_discard_and_bypass_indices;
  u32 *ipv6_inbound_protect_policy_indices;
  u32 *ipv6_inbound_policy_discard_and_bypass_indices;
} ipsec_spd_t;

typedef struct
{
  u32 spd_index;
} ip4_ipsec_config_t;

typedef struct
{
  u32 spd_index;
} ip6_ipsec_config_t;

typedef struct
{
  u32 input_sa_index;
  u32 output_sa_index;
  u32 hw_if_index;
} ipsec_tunnel_if_t;

typedef struct
{
  clib_error_t *(*add_del_sa_sess_cb) (u32 sa_index, u8 is_add);
  clib_error_t *(*check_support_cb) (ipsec_sa_t * sa);
} ipsec_main_callbacks_t;

typedef struct
{
  /* pool of tunnel instances */
  ipsec_spd_t *spds;
  ipsec_sa_t *sad;

  /* pool of tunnel interfaces */
  ipsec_tunnel_if_t *tunnel_interfaces;
  u32 *free_tunnel_if_indices;

  u32 **empty_buffers;

  uword *tunnel_index_by_key;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* next node indices */
  u32 feature_next_node_index[32];

  /* hashes */
  uword *spd_index_by_spd_id;
  uword *spd_index_by_sw_if_index;
  uword *sa_index_by_sa_id;
  uword *ipsec_if_pool_index_by_key;

  /* node indeces */
  u32 error_drop_node_index;
  u32 esp_encrypt_node_index;
  u32 esp_decrypt_node_index;
  /* next node indeces */
  u32 esp_encrypt_next_index;
  u32 esp_decrypt_next_index;

  /* callbacks */
  ipsec_main_callbacks_t cb;
} ipsec_main_t;

extern ipsec_main_t ipsec_main;

extern vlib_node_registration_t esp_encrypt_node;
extern vlib_node_registration_t esp_decrypt_node;
extern vlib_node_registration_t ipsec_if_output_node;
extern vlib_node_registration_t ipsec_if_input_node;


/*
 * functions
 */
int ipsec_set_interface_spd (vlib_main_t * vm, u32 sw_if_index, u32 spd_id,
			     int is_add);
int ipsec_add_del_spd (vlib_main_t * vm, u32 spd_id, int is_add);
int ipsec_add_del_policy (vlib_main_t * vm, ipsec_policy_t * policy,
			  int is_add);
int ipsec_add_del_sa (vlib_main_t * vm, ipsec_sa_t * new_sa, int is_add);
int ipsec_set_sa_key (vlib_main_t * vm, ipsec_sa_t * sa_update);

u32 ipsec_get_sa_index_by_sa_id (u32 sa_id);
u8 ipsec_is_sa_used (u32 sa_index);
u8 *format_ipsec_if_output_trace (u8 * s, va_list * args);
u8 *format_ipsec_policy_action (u8 * s, va_list * args);
u8 *format_ipsec_crypto_alg (u8 * s, va_list * args);
u8 *format_ipsec_integ_alg (u8 * s, va_list * args);
u8 *format_ipsec_replay_window (u8 * s, va_list * args);
uword unformat_ipsec_policy_action (unformat_input_t * input, va_list * args);
uword unformat_ipsec_crypto_alg (unformat_input_t * input, va_list * args);
uword unformat_ipsec_integ_alg (unformat_input_t * input, va_list * args);

int ipsec_add_del_tunnel_if_internal (vnet_main_t * vnm,
				      ipsec_add_del_tunnel_args_t * args,
				      u32 * sw_if_index);
int ipsec_add_del_tunnel_if (ipsec_add_del_tunnel_args_t * args);
int ipsec_add_del_ipsec_gre_tunnel (vnet_main_t * vnm,
				    ipsec_add_del_ipsec_gre_tunnel_args_t *
				    args);
int ipsec_set_interface_key (vnet_main_t * vnm, u32 hw_if_index,
			     ipsec_if_set_key_type_t type, u8 alg, u8 * key);
int ipsec_set_interface_sa (vnet_main_t * vnm, u32 hw_if_index, u32 sa_id,
			    u8 is_outbound);


/*
 *  inline functions
 */

always_inline void
ipsec_alloc_empty_buffers (vlib_main_t * vm, ipsec_main_t * im)
{
  u32 thread_index = vlib_get_thread_index ();
  uword l = vec_len (im->empty_buffers[thread_index]);
  uword n_alloc = 0;

  if (PREDICT_FALSE (l < VLIB_FRAME_SIZE))
    {
      if (!im->empty_buffers[thread_index])
	{
	  vec_alloc (im->empty_buffers[thread_index], 2 * VLIB_FRAME_SIZE);
	}

      n_alloc = vlib_buffer_alloc (vm, im->empty_buffers[thread_index] + l,
				   2 * VLIB_FRAME_SIZE - l);

      _vec_len (im->empty_buffers[thread_index]) = l + n_alloc;
    }
}

static_always_inline u32
get_next_output_feature_node_index (vlib_buffer_t * b,
				    vlib_node_runtime_t * nr)
{
  u32 next;
  u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
  vlib_main_t *vm = vlib_get_main ();
  vlib_node_t *node = vlib_get_node (vm, nr->node_index);

  vnet_feature_next (sw_if_index, &next, b);
  return node->next_nodes[next];
}

#endif /* __IPSEC_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
