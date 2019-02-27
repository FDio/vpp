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

typedef struct
{
  u32 index;
  char *name;
  u32 size;
} vlib_cdb_type_t;

typedef struct
{
  u32 index;
  char *name;
  u32 type_index;
  char *description;
  u32 size;
} vlib_cdb_class_item_t;

typedef struct
{
  u32 index;
  char *name;
  u32 size;
  vlib_cdb_class_item_t *items;
  mhash_t item_index_by_name;
} vlib_cdb_class_t;

typedef struct _vlib_cdb_type_registration_t
{
  char *name;
  u32 size;
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
  struct _vlib_cdb_class_item_registration_t *next;
} vlib_cdb_class_item_registration_t;

typedef struct
{

  /* CDB type vector and hash */
  vlib_cdb_type_t *types;
  mhash_t cdb_type_index_by_name;

  /* CDB classes vector and hash */
  vlib_cdb_class_t *classes;
  mhash_t cdb_class_index_by_name;

  /* registrations */
  vlib_cdb_type_registration_t *type_registrations;
  vlib_cdb_class_registration_t *class_registrations;
  vlib_cdb_class_item_registration_t *class_item_registrations;

} vlib_cdb_main_t;

extern vlib_cdb_main_t cdb_main;

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
