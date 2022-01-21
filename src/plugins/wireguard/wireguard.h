/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
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
#ifndef __included_wg_h__
#define __included_wg_h__

#include <wireguard/wireguard_index_table.h>
#include <wireguard/wireguard_messages.h>
#include <wireguard/wireguard_timer.h>

#define WG_DEFAULT_DATA_SIZE 2048

extern vlib_node_registration_t wg4_input_node;
extern vlib_node_registration_t wg6_input_node;
extern vlib_node_registration_t wg4_output_tun_node;
extern vlib_node_registration_t wg6_output_tun_node;

typedef struct wg_per_thread_data_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_crypto_op_t *crypto_ops;
  vnet_crypto_async_frame_t **async_frames;
  u8 data[WG_DEFAULT_DATA_SIZE];
} wg_per_thread_data_t;
typedef struct
{
  /* convenience */
  vlib_main_t *vlib_main;

  u16 msg_id_base;

  wg_index_table_t index_table;

  u32 in4_fq_index;
  u32 in6_fq_index;
  u32 out4_fq_index;
  u32 out6_fq_index;

  wg_per_thread_data_t *per_thread_data;
  u8 feature_init;

  tw_timer_wheel_16t_2w_512sl_t timer_wheel;

  /* operation mode flags (e.g. async) */
  u8 op_mode_flags;
  bool blake3;
} wg_main_t;

typedef struct
{
  /* wg post node index for async crypto */
  u32 wg4_post_next;
  u32 wg6_post_next;
} wg_async_post_next_t;

extern wg_async_post_next_t wg_encrypt_async_next;
extern wg_async_post_next_t wg_decrypt_async_next;
extern wg_main_t wg_main;

/**
 * Wireguard operation mode
 **/
#define foreach_wg_op_mode_flags _ (0, ASYNC, "async")

/**
 * Helper function to set/unset and check op modes
 **/
typedef enum wg_op_mode_flags_t_
{
#define _(v, f, s) WG_OP_MODE_FLAG_##f = 1 << v,
  foreach_wg_op_mode_flags
#undef _
} __clib_packed wg_op_mode_flags_t;

#define _(a, v, s)                                                            \
  always_inline int wg_op_mode_set_##v (void)                                 \
  {                                                                           \
    return (wg_main.op_mode_flags |= WG_OP_MODE_FLAG_##v);                    \
  }                                                                           \
  always_inline int wg_op_mode_unset_##v (void)                               \
  {                                                                           \
    return (wg_main.op_mode_flags &= ~WG_OP_MODE_FLAG_##v);                   \
  }                                                                           \
  always_inline int wg_op_mode_is_set_##v (void)                              \
  {                                                                           \
    return (wg_main.op_mode_flags & WG_OP_MODE_FLAG_##v);                     \
  }
foreach_wg_op_mode_flags
#undef _

  typedef struct
{
  u8 __pad[22];
  u16 next_index;
} wg_post_data_t;

STATIC_ASSERT (sizeof (wg_post_data_t) <=
		 STRUCT_SIZE_OF (vnet_buffer_opaque_t, unused),
	       "Custom meta-data too large for vnet_buffer_opaque_t");

#define wg_post_data(b)                                                       \
  ((wg_post_data_t *) ((u8 *) ((b)->opaque) +                                 \
		       STRUCT_OFFSET_OF (vnet_buffer_opaque_t, unused)))

#define WG_START_EVENT	1
void wg_feature_init (wg_main_t * wmp);
void wg_set_async_mode (u32 is_enabled);

#endif /* __included_wg_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
