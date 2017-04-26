/*
 *------------------------------------------------------------------
 * svmdb.h - shared VM database
 *
 * Copyright (c) 2009 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef __included_svmdb_h__
#define __included_svmdb_h__

#include "svm.h"

typedef enum
{
  SVMDB_ACTION_ILLEGAL = 0,
  SVMDB_ACTION_GET,		/* not clear why anyone would care */
  SVMDB_ACTION_SET,
  SVMDB_ACTION_UNSET,
} svmdb_action_t;

typedef struct
{
  int pid;
  int signum;
  u32 action:4;
  u32 opaque:28;
} svmdb_notify_t;

typedef struct
{
  u8 *value;
  svmdb_notify_t *notifications;
  u32 elsize;
} svmdb_value_t;

typedef enum
{
  SVMDB_NAMESPACE_STRING = 0,
  SVMDB_NAMESPACE_VEC,
  SVMDB_N_NAMESPACES,
} svmdb_namespace_t;

typedef struct
{
  uword version;
  /* pool of values */
  svmdb_value_t *values;
  uword *namespaces[SVMDB_N_NAMESPACES];
} svmdb_shm_hdr_t;

#define SVMDB_SHM_VERSION 2

typedef struct
{
  int flags;
  int pid;
  svm_region_t *db_rp;
  svmdb_shm_hdr_t *shm;
} svmdb_client_t;

typedef struct
{
  int add_del;
  svmdb_namespace_t nspace;
  char *var;
  u32 elsize;
  int signum;
  u32 action:4;
  u32 opaque:28;
} svmdb_notification_args_t;

typedef struct
{
  const char *root_path;
  uword size;
  u32 uid;
  u32 gid;
} svmdb_map_args_t;

/*
 * Must be a reasonable number, several mb smaller than
 * SVM_GLOBAL_REGION_SIZE, or no donut for you...
 */
#define SVMDB_DEFAULT_SIZE (4<<20)

svmdb_client_t *svmdb_map (svmdb_map_args_t *);

void svmdb_unmap (svmdb_client_t * client);
void svmdb_local_unset_string_variable (svmdb_client_t * client, char *var);
void svmdb_local_set_string_variable (svmdb_client_t * client,
				      char *var, char *val);
char *svmdb_local_get_string_variable (svmdb_client_t * client, char *var);
void *svmdb_local_get_variable_reference (svmdb_client_t * client,
					  svmdb_namespace_t ns, char *var);

void svmdb_local_dump_strings (svmdb_client_t * client);

void svmdb_local_unset_vec_variable (svmdb_client_t * client, char *var);
void svmdb_local_set_vec_variable (svmdb_client_t * client,
				   char *var, void *val, u32 elsize);
void *svmdb_local_get_vec_variable (svmdb_client_t * client, char *var,
				    u32 elsize);
void svmdb_local_dump_vecs (svmdb_client_t * client);

int svmdb_local_add_del_notification (svmdb_client_t * client,
				      svmdb_notification_args_t * args);

void *svmdb_local_find_or_add_vec_variable (svmdb_client_t * client,
					    char *var, u32 nbytes);

int svmdb_local_serialize_strings (svmdb_client_t * client, char *filename);
int svmdb_local_unserialize_strings (svmdb_client_t * client, char *filename);


#endif /* __included_svmdb_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
