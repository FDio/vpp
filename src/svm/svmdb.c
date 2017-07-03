/*
 *------------------------------------------------------------------
 * svmdb.c -- simple shared memory database
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/fifo.h>
#include <vppinfra/time.h>
#include <vppinfra/mheap.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>
#include <vppinfra/serialize.h>

#include "svmdb.h"

static void local_set_variable_nolock (svmdb_client_t * client,
				       svmdb_namespace_t namespace,
				       u8 * var, u8 * val, u32 elsize);

always_inline void
region_lock (svm_region_t * rp, int tag)
{
  pthread_mutex_lock (&rp->mutex);
#ifdef MUTEX_DEBUG
  rp->mutex_owner_pid = getpid ();
  rp->mutex_owner_tag = tag;
#endif
}

always_inline void
region_unlock (svm_region_t * rp)
{
#ifdef MUTEX_DEBUG
  rp->mutex_owner_pid = 0;
  rp->mutex_owner_tag = 0;
#endif
  pthread_mutex_unlock (&rp->mutex);
}

svmdb_client_t *
svmdb_map (svmdb_map_args_t * dba)
{
  svmdb_client_t *client = 0;
  svm_map_region_args_t *a = 0;
  svm_region_t *db_rp;
  void *oldheap;
  svmdb_shm_hdr_t *hp = 0;

  vec_validate (client, 0);
  vec_validate (a, 0);

  svm_region_init_chroot_uid_gid (dba->root_path, dba->uid, dba->gid);

  a->root_path = dba->root_path;
  a->name = "/db";
  a->size = dba->size ? dba->size : SVMDB_DEFAULT_SIZE;
  a->flags = SVM_FLAGS_MHEAP;
  a->uid = dba->uid;
  a->gid = dba->gid;

  db_rp = client->db_rp = svm_region_find_or_create (a);

  ASSERT (db_rp);

  vec_free (a);

  region_lock (client->db_rp, 10);
  /* Has someone else set up the shared-memory variable table? */
  if (db_rp->user_ctx)
    {
      client->shm = (void *) db_rp->user_ctx;
      client->pid = getpid ();
      region_unlock (client->db_rp);
      ASSERT (client->shm->version == SVMDB_SHM_VERSION);
      return (client);
    }
  /* Nope, it's our problem... */

  if (CLIB_DEBUG > 2)
    {
      /* Add a bogus client (pid=0) so the svm won't be deallocated */
      clib_warning
	("[%d] adding fake client (pid=0) so '%s' won't be unlinked",
	 getpid (), db_rp->region_name);
      oldheap = svm_push_pvt_heap (db_rp);
      vec_add1 (client->db_rp->client_pids, 0);
      svm_pop_heap (oldheap);
    }
  oldheap = svm_push_data_heap (db_rp);

  vec_validate (hp, 0);
  hp->version = SVMDB_SHM_VERSION;
  hp->namespaces[SVMDB_NAMESPACE_STRING]
    = hash_create_string (0, sizeof (uword));
  hp->namespaces[SVMDB_NAMESPACE_VEC]
    = hash_create_string (0, sizeof (uword));

  db_rp->user_ctx = hp;
  client->shm = hp;

  svm_pop_heap (oldheap);
  region_unlock (client->db_rp);
  client->pid = getpid ();

  return (client);
}

void
svmdb_unmap (svmdb_client_t * client)
{
  ASSERT (client);

  if (!svm_get_root_rp ())
    return;

  svm_region_unmap ((void *) client->db_rp);
  svm_region_exit ();
  vec_free (client);
}

static void
notify_value (svmdb_value_t * v, svmdb_action_t a)
{
  int i;
  int rv;
  union sigval sv;
  u32 value;
  u32 *dead_registrations = 0;

  svmdb_notify_t *np;

  for (i = 0; i < vec_len (v->notifications); i++)
    {
      np = vec_elt_at_index (v->notifications, i);
      if (np->action == a)
	{
	  value = (np->action << 28) | (np->opaque);
	  sv.sival_ptr = (void *) (uword) value;
	  do
	    {
	      rv = 0;
	      if (sigqueue (np->pid, np->signum, sv) == 0)
		break;
	      rv = errno;
	    }
	  while (rv == EAGAIN);
	  if (rv == 0)
	    continue;
	  vec_add1 (dead_registrations, i);
	}
    }

  for (i = 0; i < vec_len (dead_registrations); i++)
    {
      np = vec_elt_at_index (v->notifications, dead_registrations[i]);
      clib_warning ("dead reg pid %d sig %d action %d opaque %x",
		    np->pid, np->signum, np->action, np->opaque);
      vec_delete (v->notifications, 1, dead_registrations[i]);
    }
  vec_free (dead_registrations);
}

int
svmdb_local_add_del_notification (svmdb_client_t * client,
				  svmdb_notification_args_t * a)
{
  uword *h;
  void *oldheap;
  hash_pair_t *hp;
  svmdb_shm_hdr_t *shm;
  u8 *dummy_value = 0;
  svmdb_value_t *value;
  svmdb_notify_t *np;
  int i;
  int rv = 0;

  ASSERT (a->elsize);

  region_lock (client->db_rp, 18);
  shm = client->shm;
  oldheap = svm_push_data_heap (client->db_rp);

  h = shm->namespaces[a->nspace];

  hp = hash_get_pair_mem (h, a->var);
  if (hp == 0)
    {
      local_set_variable_nolock (client, a->nspace, (u8 *) a->var,
				 dummy_value, a->elsize);
      /* might have moved */
      h = shm->namespaces[a->nspace];
      hp = hash_get_pair_mem (h, a->var);
      ASSERT (hp);
    }

  value = pool_elt_at_index (shm->values, hp->value[0]);

  for (i = 0; i < vec_len (value->notifications); i++)
    {
      np = vec_elt_at_index (value->notifications, i);
      if ((np->pid == client->pid)
	  && (np->signum == a->signum)
	  && (np->action == a->action) && (np->opaque == a->opaque))
	{
	  if (a->add_del == 0 /* delete */ )
	    {
	      vec_delete (value->notifications, 1, i);
	      goto out;
	    }
	  else
	    {			/* add */
	      clib_warning
		("%s: ignore dup reg pid %d signum %d action %d opaque %x",
		 a->var, client->pid, a->signum, a->action, a->opaque);
	      rv = -2;
	      goto out;
	    }
	}
    }
  if (a->add_del == 0)
    {
      rv = -3;
      goto out;
    }

  vec_add2 (value->notifications, np, 1);
  np->pid = client->pid;
  np->signum = a->signum;
  np->action = a->action;
  np->opaque = a->opaque;

out:
  svm_pop_heap (oldheap);
  region_unlock (client->db_rp);
  return rv;
}


static void
local_unset_variable_nolock (svmdb_client_t * client,
			     svmdb_namespace_t namespace, char *var)
{
  uword *h;
  svmdb_value_t *oldvalue;
  hash_pair_t *hp;

  h = client->shm->namespaces[namespace];
  hp = hash_get_pair_mem (h, var);
  if (hp)
    {
      oldvalue = pool_elt_at_index (client->shm->values, hp->value[0]);
      if (vec_len (oldvalue->notifications))
	notify_value (oldvalue, SVMDB_ACTION_UNSET);
      /* zero length value means unset */
      _vec_len (oldvalue->value) = 0;
    }
  client->shm->namespaces[namespace] = h;
}

void
svmdb_local_unset_string_variable (svmdb_client_t * client, char *var)
{
  void *oldheap;

  region_lock (client->db_rp, 11);
  oldheap = svm_push_data_heap (client->db_rp);
  local_unset_variable_nolock (client, SVMDB_NAMESPACE_STRING, var);
  svm_pop_heap (oldheap);
  region_unlock (client->db_rp);
}

static void
local_set_variable_nolock (svmdb_client_t * client,
			   svmdb_namespace_t namespace,
			   u8 * var, u8 * val, u32 elsize)
{
  uword *h;
  hash_pair_t *hp;
  u8 *name;
  svmdb_shm_hdr_t *shm;

  shm = client->shm;
  h = shm->namespaces[namespace];
  hp = hash_get_pair_mem (h, var);
  if (hp)
    {
      svmdb_value_t *oldvalue;
      oldvalue = pool_elt_at_index (client->shm->values, hp->value[0]);
      vec_alloc (oldvalue->value, vec_len (val) * elsize);
      clib_memcpy (oldvalue->value, val, vec_len (val) * elsize);
      _vec_len (oldvalue->value) = vec_len (val);
      notify_value (oldvalue, SVMDB_ACTION_SET);
    }
  else
    {
      svmdb_value_t *newvalue;
      pool_get (shm->values, newvalue);
      memset (newvalue, 0, sizeof (*newvalue));
      newvalue->elsize = elsize;
      vec_alloc (newvalue->value, vec_len (val) * elsize);
      clib_memcpy (newvalue->value, val, vec_len (val) * elsize);
      _vec_len (newvalue->value) = vec_len (val);
      name = format (0, "%s%c", var, 0);
      hash_set_mem (h, name, newvalue - shm->values);
    }
  shm->namespaces[namespace] = h;
}

void
svmdb_local_set_string_variable (svmdb_client_t * client,
				 char *var, char *val)
{
  void *oldheap;

  region_lock (client->db_rp, 12);
  oldheap = svm_push_data_heap (client->db_rp);

  local_unset_variable_nolock (client, SVMDB_NAMESPACE_STRING, var);

  local_set_variable_nolock (client, SVMDB_NAMESPACE_STRING,
			     (u8 *) var, (u8 *) val, 1 /* elsize */ );
  svm_pop_heap (oldheap);
  region_unlock (client->db_rp);
}

static u8 *
local_get_variable_nolock (svmdb_client_t * client,
			   svmdb_namespace_t namespace, u8 * var)
{
  uword *h;
  uword *p;
  svmdb_shm_hdr_t *shm;
  svmdb_value_t *oldvalue;

  shm = client->shm;
  h = shm->namespaces[namespace];
  p = hash_get_mem (h, var);
  if (p)
    {
      oldvalue = pool_elt_at_index (shm->values, p[0]);
      notify_value (oldvalue, SVMDB_ACTION_GET);
      return (oldvalue->value);
    }
  return 0;
}

void *
svmdb_local_get_variable_reference (svmdb_client_t * client,
				    svmdb_namespace_t namespace, char *var)
{
  u8 *rv;

  region_lock (client->db_rp, 19);
  rv = local_get_variable_nolock (client, namespace, (u8 *) var);
  region_unlock (client->db_rp);
  return (void *) rv;
}

char *
svmdb_local_get_string_variable (svmdb_client_t * client, char *var)
{
  u8 *rv = 0;

  region_lock (client->db_rp, 13);
  rv = local_get_variable_nolock (client, SVMDB_NAMESPACE_STRING, (u8 *) var);

  if (rv && vec_len (rv))
    {
      rv = format (0, "%s", rv);
      vec_add1 (rv, 0);
    }
  region_unlock (client->db_rp);
  return ((char *) rv);
}

void
svmdb_local_dump_strings (svmdb_client_t * client)
{
  uword *h;
  u8 *key;
  u32 value;
  svmdb_shm_hdr_t *shm = client->shm;

  region_lock (client->db_rp, 14);

  h = client->shm->namespaces[SVMDB_NAMESPACE_STRING];

  /* *INDENT-OFF* */
  hash_foreach_mem(key, value, h,
  ({
    svmdb_value_t *v = pool_elt_at_index (shm->values, value);

    fformat(stdout, "%s: %s\n", key,
            vec_len(v->value) ? v->value : (u8 *)"(nil)");
  }));
  /* *INDENT-ON* */
  region_unlock (client->db_rp);
}

int
svmdb_local_serialize_strings (svmdb_client_t * client, char *filename)
{
  uword *h;
  u8 *key;
  u32 value;
  svmdb_shm_hdr_t *shm = client->shm;
  serialize_main_t _sm, *sm = &_sm;
  clib_error_t *error = 0;
  u8 *sanitized_name = 0;
  int fd = 0;

  if (strstr (filename, "..") || index (filename, '/'))
    {
      error = clib_error_return (0, "Illegal characters in filename '%s'",
				 filename);
      goto out;
    }

  sanitized_name = format (0, "/tmp/%s%c", filename, 0);

  fd = creat ((char *) sanitized_name, 0644);

  if (fd < 0)
    {
      error = clib_error_return_unix (0, "Create '%s'", sanitized_name);
      goto out;
    }

  serialize_open_unix_file_descriptor (sm, fd);

  region_lock (client->db_rp, 20);

  h = client->shm->namespaces[SVMDB_NAMESPACE_STRING];

  serialize_likely_small_unsigned_integer (sm, hash_elts (h));

  /* *INDENT-OFF* */
  hash_foreach_mem(key, value, h,
  ({
    svmdb_value_t *v = pool_elt_at_index (shm->values, value);

    /* Omit names with nil values */
    if (vec_len(v->value))
      {
        serialize_cstring (sm, (char *)key);
        serialize_cstring (sm, (char *)v->value);
      }
  }));
  /* *INDENT-ON* */
  region_unlock (client->db_rp);

  serialize_close (sm);

out:
  if (fd > 0 && close (fd) < 0)
    error = clib_error_return_unix (0, "close fd %d", fd);

  if (error)
    {
      clib_error_report (error);
      return -1;
    }
  return 0;
}

int
svmdb_local_unserialize_strings (svmdb_client_t * client, char *filename)
{
  serialize_main_t _sm, *sm = &_sm;
  void *oldheap;
  clib_error_t *error = 0;
  u8 *key, *value;
  int fd = 0;
  u32 nelts;
  int i;

  fd = open (filename, O_RDONLY);

  if (fd < 0)
    {
      error = clib_error_return_unix (0, "Failed to open '%s'", filename);
      goto out;
    }

  unserialize_open_unix_file_descriptor (sm, fd);

  region_lock (client->db_rp, 21);
  oldheap = svm_push_data_heap (client->db_rp);

  nelts = unserialize_likely_small_unsigned_integer (sm);

  for (i = 0; i < nelts; i++)
    {
      unserialize_cstring (sm, (char **) &key);
      unserialize_cstring (sm, (char **) &value);
      local_set_variable_nolock (client, SVMDB_NAMESPACE_STRING,
				 key, value, 1 /* elsize */ );
      vec_free (key);
      vec_free (value);
    }
  svm_pop_heap (oldheap);
  region_unlock (client->db_rp);

  serialize_close (sm);

out:
  if (fd > 0 && close (fd) < 0)
    error = clib_error_return_unix (0, "close fd %d", fd);

  if (error)
    {
      clib_error_report (error);
      return -1;
    }
  return 0;
}

void
svmdb_local_unset_vec_variable (svmdb_client_t * client, char *var)
{
  void *oldheap;

  region_lock (client->db_rp, 15);
  oldheap = svm_push_data_heap (client->db_rp);
  local_unset_variable_nolock (client, SVMDB_NAMESPACE_VEC, var);
  svm_pop_heap (oldheap);
  region_unlock (client->db_rp);
}

void
svmdb_local_set_vec_variable (svmdb_client_t * client,
			      char *var, void *val_arg, u32 elsize)
{
  u8 *val = (u8 *) val_arg;
  void *oldheap;

  region_lock (client->db_rp, 16);
  oldheap = svm_push_data_heap (client->db_rp);

  local_unset_variable_nolock (client, SVMDB_NAMESPACE_VEC, var);
  local_set_variable_nolock (client, SVMDB_NAMESPACE_VEC, (u8 *) var,
			     val, elsize);

  svm_pop_heap (oldheap);
  region_unlock (client->db_rp);
}

void *
svmdb_local_get_vec_variable (svmdb_client_t * client, char *var, u32 elsize)
{
  u8 *rv = 0;
  u8 *copy = 0;

  region_lock (client->db_rp, 17);

  rv = local_get_variable_nolock (client, SVMDB_NAMESPACE_VEC, (u8 *) var);

  if (rv && vec_len (rv))
    {
      /* Make a copy in process-local memory */
      vec_alloc (copy, vec_len (rv) * elsize);
      clib_memcpy (copy, rv, vec_len (rv) * elsize);
      _vec_len (copy) = vec_len (rv);
      region_unlock (client->db_rp);
      return (copy);
    }
  region_unlock (client->db_rp);
  return (0);
}

void
svmdb_local_dump_vecs (svmdb_client_t * client)
{
  uword *h;
  u8 *key;
  u32 value;
  svmdb_shm_hdr_t *shm;

  region_lock (client->db_rp, 17);
  shm = client->shm;

  h = client->shm->namespaces[SVMDB_NAMESPACE_VEC];

  /* *INDENT-OFF* */
  hash_foreach_mem(key, value, h,
  ({
    svmdb_value_t *v = pool_elt_at_index (shm->values, value);
    (void) fformat(stdout, "%s:\n %U (%.2f)\n", key,
                   format_hex_bytes, v->value,
                   vec_len(v->value)*v->elsize, ((f64 *)(v->value))[0]);
  }));
  /* *INDENT-ON* */

  region_unlock (client->db_rp);
}

void *
svmdb_local_find_or_add_vec_variable (svmdb_client_t * client,
				      char *var, u32 nbytes)
{
  void *oldheap;
  u8 *rv = 0;

  region_lock (client->db_rp, 18);
  oldheap = svm_push_data_heap (client->db_rp);

  rv = local_get_variable_nolock (client, SVMDB_NAMESPACE_VEC, (u8 *) var);

  if (rv)
    {
      goto out;
    }
  else
    {
      uword *h;
      u8 *name;
      svmdb_shm_hdr_t *shm;
      svmdb_value_t *newvalue;

      shm = client->shm;
      h = shm->namespaces[SVMDB_NAMESPACE_VEC];

      pool_get (shm->values, newvalue);
      memset (newvalue, 0, sizeof (*newvalue));
      newvalue->elsize = 1;
      vec_alloc (newvalue->value, nbytes);
      _vec_len (newvalue->value) = nbytes;
      name = format (0, "%s%c", var, 0);
      hash_set_mem (h, name, newvalue - shm->values);
      shm->namespaces[SVMDB_NAMESPACE_VEC] = h;
      rv = newvalue->value;
    }

out:
  svm_pop_heap (oldheap);
  region_unlock (client->db_rp);
  return (rv);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
