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
  /** End of the arc (optional, for consistency-checking) */
  char *last_in_arc;
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
  struct _vnet_feature_registration *next, *next_in_arc;
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

/** constraint registration object */
typedef struct _vnet_feature_constraint_registration
{
  /** next constraint set in list of all registrations*/
  struct _vnet_feature_constraint_registration *next, *next_in_arc;
  /** Feature arc name */
  char *arc_name;

  /** Feature arc index, assigned by init function */
  u8 feature_arc_index;

  /** Node names, to run in the specified order */
  char **node_names;
} vnet_feature_constraint_registration_t;

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
  vnet_feature_constraint_registration_t *next_constraint;
  vnet_feature_constraint_registration_t **next_constraint_by_arc;
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

#ifndef CLIB_MARCH_VARIANT
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
static void __vnet_rm_feature_arc_registration_##x (void)	\
  __attribute__((__destructor__)) ;				\
static void __vnet_rm_feature_arc_registration_##x (void)	\
{								\
  vnet_feature_main_t * fm = &feature_main;			\
  vnet_feature_arc_registration_t *r = &vnet_feat_arc_##x;	\
  VLIB_REMOVE_FROM_LINKED_LIST (fm->next_arc, r, next);		\
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
static void __vnet_rm_feature_registration_##x (void)		\
  __attribute__((__destructor__)) ;				\
static void __vnet_rm_feature_registration_##x (void)		\
{								\
  vnet_feature_main_t * fm = &feature_main;			\
  vnet_feature_registration_t *r = &vnet_feat_##x;		\
  VLIB_REMOVE_FROM_LINKED_LIST (fm->next_feature, r, next);	\
}								\
__VA_ARGS__ vnet_feature_registration_t vnet_feat_##x

#define VNET_FEATURE_ARC_ORDER(x,...)                                   \
  __VA_ARGS__ vnet_feature_constraint_registration_t 			\
vnet_feature_constraint_##x;                                            \
static void __vnet_add_constraint_registration_##x (void)		\
  __attribute__((__constructor__)) ;                                    \
static void __vnet_add_constraint_registration_##x (void)		\
{                                                                       \
  vnet_feature_main_t * fm = &feature_main;                             \
  vnet_feature_constraint_##x.next = fm->next_constraint;               \
  fm->next_constraint = & vnet_feature_constraint_##x;                  \
}                                                                       \
static void __vnet_rm_constraint_registration_##x (void)		\
  __attribute__((__destructor__)) ;                                     \
static void __vnet_rm_constraint_registration_##x (void)		\
{                                                                       \
  vnet_feature_main_t * fm = &feature_main;                             \
  vnet_feature_constraint_registration_t *r = &vnet_feature_constraint_##x; \
  VLIB_REMOVE_FROM_LINKED_LIST (fm->next_constraint, r, next);          \
}                                                                       \
__VA_ARGS__ vnet_feature_constraint_registration_t vnet_feature_constraint_##x

#else
#define VNET_FEATURE_ARC_INIT(x,...)				\
extern vnet_feature_arc_registration_t __clib_unused vnet_feat_arc_##x; \
static vnet_feature_arc_registration_t __clib_unused __clib_unused_vnet_feat_arc_##x
#define VNET_FEATURE_INIT(x,...)				\
extern vnet_feature_registration_t __clib_unused vnet_feat_##x; \
static vnet_feature_registration_t __clib_unused __clib_unused_vnet_feat_##x

#define VNET_FEATURE_ARC_ORDER(x,...)                           \
extern vnet_feature_constraint_registration_t                   \
__clib_unused vnet_feature_constraint_##x;                      \
static vnet_feature_constraint_registration_t __clib_unused 	\
__clib_unused_vnet_feature_constraint_##x


#endif

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

u32
vnet_feature_modify_end_node (u8 arc_index, u32 sw_if_index, u32 node_index);

static_always_inline u32
vnet_get_feature_count (u8 arc, u32 sw_if_index)
{
  vnet_feature_main_t *fm = &feature_main;
  return (fm->feature_count_by_sw_if_index[arc][sw_if_index]);
}

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
      vnet_buffer (b)->feature_arc_index = arc;
      b->current_config_index =
	vec_elt (cm->config_index_by_sw_if_index, sw_if_index);
      return vnet_get_config_data (&cm->config_main, &b->current_config_index,
				   next, n_data_bytes);
    }
  return 0;
}

static_always_inline void *
vnet_feature_arc_start_w_cfg_index (u8 arc,
				    u32 sw_if_index,
				    u32 * next,
				    vlib_buffer_t * b, u32 cfg_index)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_config_main_t *cm;
  cm = &fm->feature_config_mains[arc];

  vnet_buffer (b)->feature_arc_index = arc;
  b->current_config_index = cfg_index;

  return vnet_get_config_data (&cm->config_main, &b->current_config_index,
			       next, 0);
}

static_always_inline void
vnet_feature_arc_start (u8 arc, u32 sw_if_index, u32 * next0,
			vlib_buffer_t * b0)
{
  vnet_feature_arc_start_with_data (arc, sw_if_index, next0, b0, 0);
}

static_always_inline void *
vnet_feature_next_with_data (u32 * next0, vlib_buffer_t * b0,
			     u32 n_data_bytes)
{
  vnet_feature_main_t *fm = &feature_main;
  u8 arc = vnet_buffer (b0)->feature_arc_index;
  vnet_feature_config_main_t *cm = &fm->feature_config_mains[arc];

  return vnet_get_config_data (&cm->config_main,
			       &b0->current_config_index, next0,
			       n_data_bytes);
}

static_always_inline void
vnet_feature_next (u32 * next0, vlib_buffer_t * b0)
{
  vnet_feature_next_with_data (next0, b0, 0);
}

static_always_inline void
vnet_feature_next_u16 (u16 * next0, vlib_buffer_t * b0)
{
  u32 next32;
  vnet_feature_next_with_data (&next32, b0, 0);
  *next0 = next32;
}

static_always_inline int
vnet_device_input_have_features (u32 sw_if_index)
{
  vnet_feature_main_t *fm = &feature_main;
  return vnet_have_features (fm->device_input_feature_arc_index, sw_if_index);
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

      adv = device_input_next_node_advance[*next0];
      vlib_buffer_advance (b0, -adv);

      vnet_buffer (b0)->feature_arc_index = feature_arc_index;
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

      adv = device_input_next_node_advance[*next0];
      vlib_buffer_advance (b0, -adv);

      adv = device_input_next_node_advance[*next1];
      vlib_buffer_advance (b1, -adv);

      vnet_buffer (b0)->feature_arc_index = feature_arc_index;
      vnet_buffer (b1)->feature_arc_index = feature_arc_index;
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

      adv = device_input_next_node_advance[*next0];
      vlib_buffer_advance (b0, -adv);

      adv = device_input_next_node_advance[*next1];
      vlib_buffer_advance (b1, -adv);

      adv = device_input_next_node_advance[*next2];
      vlib_buffer_advance (b2, -adv);

      adv = device_input_next_node_advance[*next3];
      vlib_buffer_advance (b3, -adv);

      vnet_buffer (b0)->feature_arc_index = feature_arc_index;
      vnet_buffer (b1)->feature_arc_index = feature_arc_index;
      vnet_buffer (b2)->feature_arc_index = feature_arc_index;
      vnet_buffer (b3)->feature_arc_index = feature_arc_index;

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

clib_error_t *vnet_feature_arc_init
  (vlib_main_t * vm,
   vnet_config_main_t * vcm,
   char **feature_start_nodes,
   int num_feature_start_nodes,
   char *last_in_arc,
   vnet_feature_registration_t * first_reg,
   vnet_feature_constraint_registration_t * first_const_set,
   char ***in_feature_nodes);

void vnet_interface_features_show (vlib_main_t * vm, u32 sw_if_index,
				   int verbose);

typedef void (*vnet_feature_update_cb_t) (u32 sw_if_index,
					  u8 arc_index,
					  u8 is_enable, void *cb);

extern void vnet_feature_register (vnet_feature_update_cb_t cb, void *data);

#endif /* included_feature_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
