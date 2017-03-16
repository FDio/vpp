/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <vnet/api_errno.h>
#include <vnet/devices/devices.h>

/** feature registration object */
typedef struct _vnet_feature_arc_registration
{
  /** next registration in list of all registrations*/
  struct _vnet_feature_arc_registration *next;
  /** Feature Arc name */
  char *arc_name;
  /** Start nodes */
  char **start_nodes;
  int n_start_nodes;
  /* Feature arc index, assigned by init function */
  u8 feature_arc_index;
  u8 *arc_index_ptr;
} vnet_feature_arc_registration_t;

/* Enable feature callback. */
typedef clib_error_t *(vnet_feature_enable_disable_function_t)
  (u32 sw_if_index, int enable_disable);

/** feature registration object */
typedef struct _vnet_feature_registration
{
  /** next registration in list of all registrations*/
  struct _vnet_feature_registration *next;
  /** Feature arc name */
  char *arc_name;
  /** Graph node name */
  char *node_name;
  /** Pointer to this feature index, filled in by vnet_feature_arc_init */
  u32 *feature_index_ptr;
  u32 feature_index;
  /** Constraints of the form "this feature runs before X" */
  char **runs_before;
  /** Constraints of the form "this feature runs after Y" */
  char **runs_after;

  /** Function to enable/disable feature  **/
  vnet_feature_enable_disable_function_t *enable_disable_cb;
} vnet_feature_registration_t;

typedef struct vnet_feature_config_main_t_
{
  vnet_config_main_t config_main;
  u32 *config_index_by_sw_if_index;
} vnet_feature_config_main_t;

typedef struct
{
  /** feature arc configuration list */
  vnet_feature_arc_registration_t *next_arc;
  uword **arc_index_by_name;

  /** feature path configuration lists */
  vnet_feature_registration_t *next_feature;
  vnet_feature_registration_t **next_feature_by_arc;
  uword **next_feature_by_name;

  /** feature config main objects */
  vnet_feature_config_main_t *feature_config_mains;

  /** Save partial order results for show command */
  char ***feature_nodes;

  /** bitmap of interfaces which have driver rx features configured */
  uword **sw_if_index_has_features;

  /** feature reference counts by interface */
  i16 **feature_count_by_sw_if_index;

  /** Feature arc index for device-input */
  u8 device_input_feature_arc_index;

  /** convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} vnet_feature_main_t;

extern vnet_feature_main_t feature_main;

#define VNET_FEATURE_ARC_INIT(x,...)				\
  __VA_ARGS__ vnet_feature_arc_registration_t vnet_feat_arc_##x;\
static void __vnet_add_feature_arc_registration_##x (void)	\
  __attribute__((__constructor__)) ;				\
static void __vnet_add_feature_arc_registration_##x (void)	\
{								\
  vnet_feature_main_t * fm = &feature_main;			\
  vnet_feat_arc_##x.next = fm->next_arc;			\
  fm->next_arc = & vnet_feat_arc_##x;				\
}								\
__VA_ARGS__ vnet_feature_arc_registration_t vnet_feat_arc_##x

#define VNET_FEATURE_INIT(x,...)				\
  __VA_ARGS__ vnet_feature_registration_t vnet_feat_##x;	\
static void __vnet_add_feature_registration_##x (void)		\
  __attribute__((__constructor__)) ;				\
static void __vnet_add_feature_registration_##x (void)		\
{								\
  vnet_feature_main_t * fm = &feature_main;			\
  vnet_feat_##x.next = fm->next_feature;			\
  fm->next_feature = & vnet_feat_##x;				\
}								\
__VA_ARGS__ vnet_feature_registration_t vnet_feat_##x

void
vnet_config_update_feature_count (vnet_feature_main_t * fm, u8 arc,
				  u32 sw_if_index, int is_add);

u32 vnet_get_feature_index (u8 arc, const char *s);
u8 vnet_get_feature_arc_index (const char *s);
vnet_feature_registration_t *vnet_get_feature_reg (const char *arc_name,
						   const char *node_name);


int
vnet_feature_enable_disable_with_index (u8 arc_index, u32 feature_index,
					u32 sw_if_index, int enable_disable,
					void *feature_config,
					u32 n_feature_config_bytes);

int
vnet_feature_enable_disable (const char *arc_name, const char *node_name,
			     u32 sw_if_index, int enable_disable,
			     void *feature_config,
			     u32 n_feature_config_bytes);

static inline vnet_feature_config_main_t *
vnet_get_feature_arc_config_main (u8 arc_index)
{
  vnet_feature_main_t *fm = &feature_main;

  if (arc_index == (u8) ~ 0)
    return 0;

  return &fm->feature_config_mains[arc_index];
}

static_always_inline vnet_feature_config_main_t *
vnet_feature_get_config_main (u16 arc)
{
  vnet_feature_main_t *fm = &feature_main;
  return &fm->feature_config_mains[arc];
}

static_always_inline int
vnet_have_features (u8 arc, u32 sw_if_index)
{
  vnet_feature_main_t *fm = &feature_main;
  return clib_bitmap_get (fm->sw_if_index_has_features[arc], sw_if_index);
}

static_always_inline u32
vnet_get_feature_config_index (u8 arc, u32 sw_if_index)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_config_main_t *cm = &fm->feature_config_mains[arc];
  return vec_elt (cm->config_index_by_sw_if_index, sw_if_index);
}

static_always_inline void *
vnet_feature_arc_start_with_data (u8 arc, u32 sw_if_index, u32 * next,
				  vlib_buffer_t * b, u32 n_data_bytes)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_config_main_t *cm;
  cm = &fm->feature_config_mains[arc];

  if (PREDICT_FALSE (vnet_have_features (arc, sw_if_index)))
    {
      b->feature_arc_index = arc;
      b->current_config_index =
	vec_elt (cm->config_index_by_sw_if_index, sw_if_index);
      return vnet_get_config_data (&cm->config_main, &b->current_config_index,
				   next, n_data_bytes);
    }
  return 0;
}

static_always_inline void
vnet_feature_arc_start (u8 arc, u32 sw_if_index, u32 * next0,
			vlib_buffer_t * b0)
{
  vnet_feature_arc_start_with_data (arc, sw_if_index, next0, b0, 0);
}

static_always_inline void *
vnet_feature_next_with_data (u32 sw_if_index, u32 * next0,
			     vlib_buffer_t * b0, u32 n_data_bytes)
{
  vnet_feature_main_t *fm = &feature_main;
  u8 arc = b0->feature_arc_index;
  vnet_feature_config_main_t *cm = &fm->feature_config_mains[arc];

  return vnet_get_config_data (&cm->config_main,
			       &b0->current_config_index, next0,
			       n_data_bytes);
}

static_always_inline void
vnet_feature_next (u32 sw_if_index, u32 * next0, vlib_buffer_t * b0)
{
  vnet_feature_next_with_data (sw_if_index, next0, b0, 0);
}

static_always_inline void
vnet_feature_start_device_input_x1 (u32 sw_if_index, u32 * next0,
				    vlib_buffer_t * b0)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_config_main_t *cm;
  u8 feature_arc_index = fm->device_input_feature_arc_index;
  cm = &fm->feature_config_mains[feature_arc_index];

  if (PREDICT_FALSE
      (clib_bitmap_get
       (fm->sw_if_index_has_features[feature_arc_index], sw_if_index)))
    {
      /*
       * Save next0 so that the last feature in the chain
       * can skip ethernet-input if indicated...
       */
      u16 adv;

      vnet_buffer (b0)->device_input_feat.saved_next_index = *next0;
      adv = device_input_next_node_advance[*next0];
      vnet_buffer (b0)->device_input_feat.buffer_advance = adv;
      vlib_buffer_advance (b0, -adv);

      b0->feature_arc_index = feature_arc_index;
      b0->current_config_index =
	vec_elt (cm->config_index_by_sw_if_index, sw_if_index);
      vnet_get_config_data (&cm->config_main, &b0->current_config_index,
			    next0, /* # bytes of config data */ 0);
    }
}

static_always_inline void
vnet_feature_start_device_input_x2 (u32 sw_if_index,
				    u32 * next0,
				    u32 * next1,
				    vlib_buffer_t * b0, vlib_buffer_t * b1)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_config_main_t *cm;
  u8 feature_arc_index = fm->device_input_feature_arc_index;
  cm = &fm->feature_config_mains[feature_arc_index];

  if (PREDICT_FALSE
      (clib_bitmap_get
       (fm->sw_if_index_has_features[feature_arc_index], sw_if_index)))
    {
      /*
       * Save next0 so that the last feature in the chain
       * can skip ethernet-input if indicated...
       */
      u16 adv;

      vnet_buffer (b0)->device_input_feat.saved_next_index = *next0;
      adv = device_input_next_node_advance[*next0];
      vnet_buffer (b0)->device_input_feat.buffer_advance = adv;
      vlib_buffer_advance (b0, -adv);

      vnet_buffer (b1)->device_input_feat.saved_next_index = *next1;
      adv = device_input_next_node_advance[*next1];
      vnet_buffer (b1)->device_input_feat.buffer_advance = adv;
      vlib_buffer_advance (b1, -adv);

      b0->feature_arc_index = feature_arc_index;
      b1->feature_arc_index = feature_arc_index;
      b0->current_config_index =
	vec_elt (cm->config_index_by_sw_if_index, sw_if_index);
      b1->current_config_index = b0->current_config_index;
      vnet_get_config_data (&cm->config_main, &b0->current_config_index,
			    next0, /* # bytes of config data */ 0);
      vnet_get_config_data (&cm->config_main, &b1->current_config_index,
			    next1, /* # bytes of config data */ 0);
    }
}

static_always_inline void
vnet_feature_start_device_input_x4 (u32 sw_if_index,
				    u32 * next0,
				    u32 * next1,
				    u32 * next2,
				    u32 * next3,
				    vlib_buffer_t * b0,
				    vlib_buffer_t * b1,
				    vlib_buffer_t * b2, vlib_buffer_t * b3)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_config_main_t *cm;
  u8 feature_arc_index = fm->device_input_feature_arc_index;
  cm = &fm->feature_config_mains[feature_arc_index];

  if (PREDICT_FALSE
      (clib_bitmap_get
       (fm->sw_if_index_has_features[feature_arc_index], sw_if_index)))
    {
      /*
       * Save next0 so that the last feature in the chain
       * can skip ethernet-input if indicated...
       */
      u16 adv;

      vnet_buffer (b0)->device_input_feat.saved_next_index = *next0;
      adv = device_input_next_node_advance[*next0];
      vnet_buffer (b0)->device_input_feat.buffer_advance = adv;
      vlib_buffer_advance (b0, -adv);

      vnet_buffer (b1)->device_input_feat.saved_next_index = *next1;
      adv = device_input_next_node_advance[*next1];
      vnet_buffer (b1)->device_input_feat.buffer_advance = adv;
      vlib_buffer_advance (b1, -adv);

      vnet_buffer (b2)->device_input_feat.saved_next_index = *next2;
      adv = device_input_next_node_advance[*next2];
      vnet_buffer (b2)->device_input_feat.buffer_advance = adv;
      vlib_buffer_advance (b2, -adv);

      vnet_buffer (b3)->device_input_feat.saved_next_index = *next3;
      adv = device_input_next_node_advance[*next3];
      vnet_buffer (b3)->device_input_feat.buffer_advance = adv;
      vlib_buffer_advance (b3, -adv);

      b0->feature_arc_index = feature_arc_index;
      b1->feature_arc_index = feature_arc_index;
      b2->feature_arc_index = feature_arc_index;
      b3->feature_arc_index = feature_arc_index;

      b0->current_config_index =
	vec_elt (cm->config_index_by_sw_if_index, sw_if_index);
      b1->current_config_index = b0->current_config_index;
      b2->current_config_index = b0->current_config_index;
      b3->current_config_index = b0->current_config_index;

      vnet_get_config_data (&cm->config_main, &b0->current_config_index,
			    next0, /* # bytes of config data */ 0);
      vnet_get_config_data (&cm->config_main, &b1->current_config_index,
			    next1, /* # bytes of config data */ 0);
      vnet_get_config_data (&cm->config_main, &b2->current_config_index,
			    next2, /* # bytes of config data */ 0);
      vnet_get_config_data (&cm->config_main, &b3->current_config_index,
			    next3, /* # bytes of config data */ 0);
    }
}

#define VNET_FEATURES(...)  (char*[]) { __VA_ARGS__, 0}

clib_error_t *vnet_feature_arc_init (vlib_main_t * vm,
				     vnet_config_main_t * vcm,
				     char **feature_start_nodes,
				     int num_feature_start_nodes,
				     vnet_feature_registration_t *
				     first_reg, char ***feature_nodes);

void vnet_interface_features_show (vlib_main_t * vm, u32 sw_if_index);

#endif /* included_feature_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
