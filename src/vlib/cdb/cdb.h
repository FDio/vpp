/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef included_vlib_cdb_h
#define included_vlib_cdb_h

#include <vppinfra/format.h>
#include <vppinfra/mhash.h>

typedef int (*cdb_compare_function_t) (void *, void *);

typedef enum
{
  CDB_FIELD_ACTION_UNINITIALIZED = 0,
  CDB_FIELD_ACTION_SET,
  CDB_FIELD_ACTION_UNSET,
} vlib_cdb_field_action_t;

typedef enum
{
  CDB_OBJECT_ACTION_CREATE,
  CDB_OBJECT_ACTION_EDIT,
  CDB_OBJECT_ACTION_DELETE,
} vlib_cdb_object_action_t;

typedef struct
{
  u32 index;
  char *name;
  u32 size;
  u8 is_pointer_type;
  unformat_function_t *unformat;
  format_function_t *format;
  cdb_compare_function_t compare;
} vlib_cdb_type_t;

typedef struct
{
  u32 index;
  char *name;
  u32 type_index;
  char *description;

#define CDB_CLASS_ITEM_IS_MULTIPLE (1 << 0)
  u32 flags;
} vlib_cdb_class_item_t;

typedef struct
{
  void *value;
  vlib_cdb_field_action_t action;
} vlib_cdb_object_field_t;

typedef struct
{
  u8 *name;
  u32 class_index;
  vlib_cdb_object_action_t action;
  vlib_cdb_object_field_t **values;
} vlib_cdb_object_t;

typedef clib_error_t * (*vlib_cdb_verify_object_callback_t)
  (char * class, vlib_cdb_object_t *o, vlib_cdb_object_action_t action,
   u8 is_verify);

typedef clib_error_t * (*vlib_cdb_verify_item_callback_t) (char * class,
    vlib_cdb_object_t *o, vlib_cdb_class_item_t * ci, void * value,
    vlib_cdb_field_action_t action, u8 is_verify);

typedef struct
{
  u32 index;
  char *name;
  u32 size;
  vlib_cdb_class_item_t *items;
  mhash_t item_index_by_name;

  vlib_cdb_verify_object_callback_t *ocbs;
  vlib_cdb_verify_item_callback_t *icbs;
} vlib_cdb_class_t;

typedef struct _vlib_cdb_type_registration_t
{
  char *name;
  u32 size;
  u8 is_pointer_type;
  unformat_function_t *unformat;
  format_function_t *format;
  cdb_compare_function_t compare;
  struct _vlib_cdb_type_registration_t *next;
} vlib_cdb_type_registration_t;

typedef struct _vlib_cdb_class_registration_t
{
  char *name;
  struct _vlib_cdb_class_registration_t *next;
} vlib_cdb_class_registration_t;

typedef struct _vlib_cdb_class_item_registration_t
{
  char *class;
  char *name;
  char *type;
  char *description;
  u32 flags;
  struct _vlib_cdb_class_item_registration_t *next;
} vlib_cdb_class_item_registration_t;

typedef struct
{
  uword *obj_index_by_obj_key;
  vlib_cdb_object_t *objs;
} vlib_cdb_config_datastore_t;

typedef struct
{
  u32 class_index;
  uword name_hash;
} vlib_cdb_class_object_key_t;

typedef struct
{
  /* index of currently modified object in candidate datastore */
  u32 current_cds_obj_index;

  /* CDB type vector and hash */
  vlib_cdb_type_t *types;
  mhash_t cdb_type_index_by_name;

  /* CDB classes vector and hash */
  vlib_cdb_class_t *classes;
  mhash_t cdb_class_index_by_name;

  vlib_cdb_config_datastore_t running;
  vlib_cdb_config_datastore_t candidate;

  /* registrations */
  vlib_cdb_type_registration_t *type_registrations;
  vlib_cdb_class_registration_t *class_registrations;
  vlib_cdb_class_item_registration_t *class_item_registrations;

} vlib_cdb_main_t;

extern vlib_cdb_main_t cdb_main;

int vlib_cdb_create_class_object (u8 * cls_name, u8 * obj_name);
int vlib_cdb_edit_class_object (u8 * cls_name, u8 * obj_name);
int vlib_cdb_delete_class_object (u8 * cls_name, u8 * obj_name);
int vlib_cdb_set_field_value (u8 * field, u8 * value);
int vlib_cdb_unset_field (u8 * field, u8 * value);
int vlib_cdb_commit (void);
int vlib_cdb_clear_candidate_config (void);

int vlib_cdb_register_commit_cb (char *class,
    vlib_cdb_verify_object_callback_t ocb,
    vlib_cdb_verify_item_callback_t icb);

static_always_inline vlib_cdb_config_datastore_t *
vlib_cdb_get_candidate_ds (void)
{
  vlib_cdb_main_t *cm = &cdb_main;
  return &cm->candidate;
}

static_always_inline vlib_cdb_config_datastore_t *
vlib_cdb_get_running_ds (void)
{
  vlib_cdb_main_t *cm = &cdb_main;
  return &cm->running;
}

#define VLIB_REGISTER_CDB_TYPE(x)                                       \
  vlib_cdb_type_registration_t __vlib_cdb_type_##x;                     \
static void __clib_constructor __vlib_cdb_type_registration_##x (void)  \
{                                                                       \
    vlib_cdb_main_t * cm = &cdb_main;                                   \
    __vlib_cdb_type_##x.next = cm->type_registrations;                  \
    cm->type_registrations = & __vlib_cdb_type_##x;                     \
}                                                                       \
vlib_cdb_type_registration_t __vlib_cdb_type_##x

#define VLIB_REGISTER_CDB_CLASS(x)                                      \
  vlib_cdb_class_registration_t __vlib_cdb_class_##x;                   \
static void __clib_constructor __vlib_cdb_class_registration_##x (void) \
{                                                                       \
    vlib_cdb_main_t * cm = &cdb_main;                                   \
    __vlib_cdb_class_##x.next = cm->class_registrations;                \
    cm->class_registrations = & __vlib_cdb_class_##x;                   \
}                                                                       \
vlib_cdb_class_registration_t __vlib_cdb_class_##x

#define VLIB_REGISTER_CDB_CLASS_ITEM(x)                                      \
  vlib_cdb_class_item_registration_t __vlib_cdb_class_item_##x;              \
static void __clib_constructor __vlib_cdb_class_item_registration_##x (void) \
{                                                                            \
    vlib_cdb_main_t * cm = &cdb_main;                                        \
    __vlib_cdb_class_item_##x.next = cm->class_item_registrations;           \
    cm->class_item_registrations = & __vlib_cdb_class_item_##x;              \
}                                                                            \
vlib_cdb_class_item_registration_t __vlib_cdb_class_item_##x

#endif /* included_vlib_cdb_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
