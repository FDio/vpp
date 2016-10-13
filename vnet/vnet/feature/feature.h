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

#ifndef included_features_h
#define included_features_h

#include <vnet/vnet.h>

#define foreach_vnet_feature_type \
  _(DEVICE_INPUT, device_input, "device-input")

typedef enum
{
#define _(n, l, s) VNET_FEAT_##n,
  foreach_vnet_feature_type
#undef _
    VNET_N_FEAT_TYPES,
} vnet_feature_type_t;

/** feature registration object */
typedef struct _vnet_feature_registration
{
  /** next registration in list of all registrations*/
  struct _vnet_feature_registration *next;
  /** Graph node name */
  char *node_name;
  /** Pointer to this feature index, filled in by vnet_feature_arc_init */
  u32 *feature_index;
  u32 feature_index_u32;
  /** Constraints of the form "this feature runs before X" */
  char **runs_before;
  /** Constraints of the form "this feature runs after Y" */
  char **runs_after;
} vnet_feature_registration_t;

typedef struct ip_config_main_t_
{
  vnet_config_main_t config_main;
  u32 *config_index_by_sw_if_index;
} ip_config_main_t;

typedef struct
{
  /** feature path configuration lists */
  vnet_feature_registration_t *next_feature[VNET_N_FEAT_TYPES];
  uword *next_feature_by_name[VNET_N_FEAT_TYPES];

  /** feature config main objects */
  ip_config_main_t feature_config_mains[VNET_N_FEAT_TYPES];

  /** Save partial order results for show command */
  char **feature_nodes[VNET_N_FEAT_TYPES];

  /** bitmap of interfaces which have driver rx features configured */
  uword *sw_if_index_has_driver_rx_features;

  /** driver rx feature reference counts by interface */
  i16 *driver_rx_feature_count_by_sw_if_index;

  /** convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} vnet_feature_main_t;

extern vnet_feature_main_t feature_main;

#define VNET_FEATURE_INIT(t, x,...)                             \
  __VA_ARGS__ vnet_feature_registration_t t##_##x;        \
static void __vnet_add_feature_registration_##t##_##x (void)    \
  __attribute__((__constructor__)) ;                            \
static void __vnet_add_feature_registration_##t##_##x (void)      \
{                                                               \
  vnet_feature_main_t * fm = &feature_main;                     \
  t##_##x.next = fm->next_feature[VNET_FEAT_##t];         \
  fm->next_feature[VNET_FEAT_##t] = & t##_##x;         \
}                                                               \
__VA_ARGS__ vnet_feature_registration_t t##_##x

void
vnet_config_update_driver_rx_feature_count (vnet_feature_main_t * fm,
					    u32 sw_if_index, int is_add);

u32 vnet_feature_index_from_node_name (const char *s);

void
vnet_feature_device_input_enable_disable (const char *node_name,
					  u32 sw_if_index,
					  int enable_disable);


static_always_inline void
vlib_feature_device_input_redirect_x1 (u32 sw_if_index, u32 * next0,
				       vlib_buffer_t * b0,
				       u16 buffer_advanced0)
{
  vnet_feature_main_t *fm = &feature_main;
  ip_config_main_t *cm = &fm->feature_config_mains[VNET_FEAT_DEVICE_INPUT];

  if (PREDICT_FALSE
      (clib_bitmap_get (fm->sw_if_index_has_driver_rx_features, sw_if_index)))
    {
      /*
       * Save next0 so that the last feature in the chain
       * can skip ethernet-input if indicated...
       */
      vnet_buffer (b0)->device_input_feat.saved_next_index = *next0;
      vnet_buffer (b0)->device_input_feat.buffer_advance = buffer_advanced0;
      vlib_buffer_advance (b0, -buffer_advanced0);

      b0->current_config_index =
	vec_elt (cm->config_index_by_sw_if_index, sw_if_index);
      vnet_get_config_data (&cm->config_main, &b0->current_config_index,
			    next0, /* # bytes of config data */ 0);
    }
}

#define ORDER_CONSTRAINTS (char*[])

clib_error_t *vnet_feature_arc_init (vlib_main_t * vm,
				     vnet_config_main_t * vcm,
				     char **feature_start_nodes,
				     int num_feature_start_nodes,
				     vnet_feature_registration_t *
				     first_reg, char ***feature_nodes);

void ip_interface_features_show (vlib_main_t * vm,
				 const char *pname,
				 ip_config_main_t * cm, u32 sw_if_index);

#endif /* included_feature_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
