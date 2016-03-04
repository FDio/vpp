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
#if DPDK==1
#include <vnet/devices/dpdk/dpdk.h>
#endif

#define foreach_ipsec_policy_action \
  _(0, BYPASS,  "bypass")          \
  _(1, DISCARD, "discard")         \
  _(2, RESOLVE, "resolve")         \
  _(3, PROTECT, "protect")

typedef enum {
#define _(v,f,s) IPSEC_POLICY_ACTION_##f = v,
  foreach_ipsec_policy_action
#undef _
  IPSEC_POLICY_N_ACTION,
} ipsec_policy_action_t;

#define foreach_ipsec_crypto_alg \
  _(0, NONE,  "none")               \
  _(1, AES_CBC_128, "aes-cbc-128")  \
  _(2, AES_CBC_192, "aes-cbc-192")  \
  _(3, AES_CBC_256, "aes-cbc-256")

typedef enum {
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
  _(6, SHA_512_256, "sha-512-256") /* RFC4868 */

typedef enum {
#define _(v,f,s) IPSEC_INTEG_ALG_##f = v,
  foreach_ipsec_integ_alg
#undef _
  IPSEC_INTEG_N_ALG,
} ipsec_integ_alg_t;

typedef enum {
	IPSEC_PROTOCOL_AH = 0,
	IPSEC_PROTOCOL_ESP = 1
} ipsec_protocol_t;

typedef struct {
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

    /* runtime */
    u32 seq;
    u32 seq_hi;
    u32 last_seq;
    u32 last_seq_hi;
    u64 replay_window;
} ipsec_sa_t;

typedef struct {
  ip46_address_t start, stop;
} ip46_address_range_t;

typedef struct {
  u16 start, stop;
} port_range_t;

typedef struct {
  u8 is_add;
  u8 esn;
  u8 anti_replay;
  ip4_address_t local_ip, remote_ip;
  u32 local_spi;
  u32 remote_spi;
} ipsec_add_del_tunnel_args_t;

typedef enum {
  IPSEC_IF_SET_KEY_TYPE_NONE,
  IPSEC_IF_SET_KEY_TYPE_LOCAL_CRYPTO,
  IPSEC_IF_SET_KEY_TYPE_REMOTE_CRYPTO,
  IPSEC_IF_SET_KEY_TYPE_LOCAL_INTEG,
  IPSEC_IF_SET_KEY_TYPE_REMOTE_INTEG,
} ipsec_if_set_key_type_t;

typedef  struct {
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

typedef struct {
	u32 id;
	/* pool of policies */
	ipsec_policy_t * policies;
        /* vectors of policy indices */
	u32 * ipv4_outbound_policies;
	u32 * ipv6_outbound_policies;
	u32 * ipv4_inbound_protect_policy_indices;
	u32 * ipv4_inbound_policy_discard_and_bypass_indices;
        u32 * ipv6_inbound_protect_policy_indices;
        u32 * ipv6_inbound_policy_discard_and_bypass_indices;
} ipsec_spd_t;

typedef struct {
  u32 spd_index;
} ip4_ipsec_config_t;

typedef struct {
  u32 spd_index;
} ip6_ipsec_config_t;

typedef struct {
  u32 input_sa_index;
  u32 output_sa_index;
  u32 hw_if_index;
} ipsec_tunnel_if_t;

typedef struct {
  /* pool of tunnel instances */
  ipsec_spd_t * spds;
  ipsec_sa_t * sad;

  /* pool of tunnel interfaces */
  ipsec_tunnel_if_t * tunnel_interfaces;
  u32 * free_tunnel_if_indices;

  u32 * empty_buffers;

  uword * tunnel_index_by_key;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* next node indices */
  u32 feature_next_node_index[32];

  /* hashes */
  uword * spd_index_by_spd_id;
  uword * spd_index_by_sw_if_index;
  uword * sa_index_by_sa_id;
  uword * ipsec_if_pool_index_by_key;

  /* node indexes */
  u32 error_drop_node_index;
  u32 ip4_lookup_node_index;
  u32 esp_encrypt_node_index;

} ipsec_main_t;

ipsec_main_t ipsec_main;

extern vlib_node_registration_t esp_encrypt_node;
extern vlib_node_registration_t esp_decrypt_node;
extern vlib_node_registration_t ipsec_if_output_node;
extern vlib_node_registration_t ipsec_if_input_node;


/*
 * functions
 */
int ipsec_set_interface_spd(vlib_main_t * vm, u32 sw_if_index, u32 spd_id, int is_add);
int ipsec_add_del_spd(vlib_main_t * vm, u32 spd_id, int is_add);
int ipsec_add_del_policy(vlib_main_t * vm, ipsec_policy_t * policy, int is_add);
int ipsec_add_del_sa(vlib_main_t * vm, ipsec_sa_t * new_sa, int is_add);
int ipsec_set_sa_key(vlib_main_t * vm, ipsec_sa_t * sa_update);

u8 * format_ipsec_if_output_trace (u8 * s, va_list * args);
u8 * format_ipsec_policy_action (u8 * s, va_list * args);
u8 * format_ipsec_crypto_alg (u8 * s, va_list * args);
u8 * format_ipsec_integ_alg (u8 * s, va_list * args);
u8 * format_ipsec_replay_window(u8 * s, va_list * args);
uword unformat_ipsec_policy_action (unformat_input_t * input, va_list * args);
uword unformat_ipsec_crypto_alg (unformat_input_t * input, va_list * args);
uword unformat_ipsec_integ_alg (unformat_input_t * input, va_list * args);

u32 ipsec_add_del_tunnel_if (vnet_main_t * vnm, ipsec_add_del_tunnel_args_t * args);
int ipsec_set_interface_key(vnet_main_t * vnm, u32 hw_if_index, ipsec_if_set_key_type_t type, u8 alg, u8 * key);


/*
 *  inline functions
 */

always_inline void
ipsec_alloc_empty_buffers(vlib_main_t * vm, ipsec_main_t *im)
{
#if DPDK==1
  dpdk_main_t * dm = &dpdk_main;
  u32 free_list_index = dm->vlib_buffer_free_list_index;
#else
  u32 free_list_index = VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX;
#endif
  uword l = vec_len (im->empty_buffers);
  uword n_alloc = 0;

  if (PREDICT_FALSE(l < VLIB_FRAME_SIZE))
    {
      if (!im->empty_buffers) {
        vec_alloc (im->empty_buffers, 2 * VLIB_FRAME_SIZE );
      }

      n_alloc = vlib_buffer_alloc_from_free_list (vm, im->empty_buffers + l,
                                                  2 * VLIB_FRAME_SIZE - l,
                                                  free_list_index);

      _vec_len (im->empty_buffers) = l + n_alloc;
    }
}

static_always_inline u32 /* FIXME move to interface???.h */
get_next_output_feature_node_index( vnet_main_t * vnm,
                                    vlib_buffer_t * b)
{
  vlib_main_t * vm = vlib_get_main();
  vlib_node_t * node;
  u32 r;
  intf_output_feat_t next_feature;

  u8 * node_names[] = {
#define _(sym, str) (u8 *) str,
    foreach_intf_output_feat
#undef _
  };

  count_trailing_zeros(next_feature, vnet_buffer(b)->output_features.bitmap);

  if (next_feature >= INTF_OUTPUT_FEAT_DONE)
    {
      u32 sw_if_index = vnet_buffer(b)->sw_if_index[VLIB_TX];
      vnet_hw_interface_t * hw = vnet_get_sup_hw_interface(vnm, sw_if_index);
      r = hw->output_node_index;
    }
  else
    {
      vnet_buffer(b)->output_features.bitmap &= ~(1 << next_feature);
      /* FIXME */
      node = vlib_get_node_by_name(vm, node_names[next_feature]);
      r = node->index;
    }

  return r;
}
