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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
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

typedef struct
{
  svmdb_map_args_t map_args;
  int uid, gid;
  uword size;
} svmdbtool_main_t;

svmdbtool_main_t svmdbtool_main;

static inline svmdb_map_args_t *
map_arg_setup (char *chroot_path)
{
  svmdbtool_main_t *sm = &svmdbtool_main;
  svmdb_map_args_t *ma = &sm->map_args;

  clib_memset (ma, 0, sizeof (*ma));
  ma->root_path = chroot_path;
  ma->size = sm->size;
  ma->uid = sm->uid;
  ma->gid = sm->gid;
  return ma;
}

static void
get_string (char *chroot_path, u8 * vbl)
{
  svmdb_client_t *c;
  char *rv;
  svmdb_map_args_t *ma;

  ma = map_arg_setup (chroot_path);

  c = svmdb_map (ma);

  rv = svmdb_local_get_string_variable (c, (char *) vbl);

  fformat (stdout, "%s\n", rv ? rv : "UNSET");
  vec_free (rv);
  svmdb_unmap (c);
}

static void
set_string (char *chroot_path, u8 * vbl, u8 * value)
{
  svmdb_client_t *c;
  svmdb_map_args_t *ma;

  ma = map_arg_setup (chroot_path);

  c = svmdb_map (ma);
  svmdb_local_set_string_variable (c, (char *) vbl, (char *) value);
  svmdb_unmap (c);
}

static void
unset_string (char *chroot_path, u8 * vbl)
{
  svmdb_client_t *c;
  svmdb_map_args_t *ma;

  ma = map_arg_setup (chroot_path);

  c = svmdb_map (ma);
  svmdb_local_unset_string_variable (c, (char *) vbl);
  svmdb_unmap (c);
}

static void
dump_strings (char *chroot_path)
{
  svmdb_client_t *c;
  svmdb_map_args_t *ma;

  ma = map_arg_setup (chroot_path);

  c = svmdb_map (ma);
  svmdb_local_dump_strings (c);
  svmdb_unmap (c);
}

static void
serialize_strings (char *chroot_path, char *filename)
{
  svmdb_client_t *c;
  svmdb_map_args_t *ma;

  ma = map_arg_setup (chroot_path);

  c = svmdb_map (ma);
  (void) svmdb_local_serialize_strings (c, filename);
  svmdb_unmap (c);
}

static void
unserialize_strings (char *chroot_path, char *filename)
{
  svmdb_client_t *c;
  svmdb_map_args_t *ma;

  ma = map_arg_setup (chroot_path);

  c = svmdb_map (ma);
  (void) svmdb_local_unserialize_strings (c, filename);
  svmdb_unmap (c);
}

static void
test_vlib_vec_rate (char *chroot_path, f64 vr)
{
  svmdb_client_t *c;
  f64 *tv = 0;
  svmdb_map_args_t *ma;

  ma = map_arg_setup (chroot_path);

  c = svmdb_map (ma);

  vec_add1 (tv, vr);

  svmdb_local_set_vec_variable (c, "vlib_vector_rate", (char *) tv,
				sizeof (*tv));
  svmdb_unmap (c);

  vec_free (tv);
}



static void
test_vec (char *chroot_path, u8 * vbl)
{
  svmdb_client_t *c;
  u64 *tv = 0;
  int i;
  svmdb_map_args_t *ma;

  ma = map_arg_setup (chroot_path);

  c = svmdb_map (ma);

  /* my amp goes to 11 */
  for (i = 0; i < 11; i++)
    {
      vec_add1 (tv, i);
    }

  svmdb_local_set_vec_variable (c, (char *) vbl, (char *) tv, sizeof (tv[0]));
  svmdb_unmap (c);

  vec_free (tv);
}

static void
fake_install (char *chroot_path, u8 * add_value)
{
  svmdb_client_t *c;
  u8 *v = 0;
  u8 **values = 0;
  u8 *oldvalue;
  u8 *value;
  int nitems = 0, i;
  serialize_main_t m;
  svmdb_map_args_t *ma;

  ma = map_arg_setup (chroot_path);

  c = svmdb_map (ma);

  oldvalue = svmdb_local_get_vec_variable (c, "installed_sw", 1);
  if (oldvalue)
    {
      unserialize_open_data (&m, oldvalue, vec_len (oldvalue));
      nitems = unserialize_likely_small_unsigned_integer (&m);
      for (i = 0; i < nitems; i++)
	{
	  unserialize_cstring (&m, (char **) &value);
	  vec_add1 (values, value);
	}
      vec_free (v);
    }
  nitems++;
  value = format (0, "%s%c", add_value, 0);

  vec_add1 (values, value);

  fformat (stdout, "Resulting installed_sw vector:\n");

  serialize_open_vector (&m, v);
  serialize_likely_small_unsigned_integer (&m, vec_len (values));
  for (i = 0; i < vec_len (values); i++)
    {
      fformat (stdout, "%s\n", values[i]);
      serialize_cstring (&m, (char *) values[i]);
    }

  v = serialize_close_vector (&m);

  svmdb_local_set_vec_variable (c, "installed_sw", v, sizeof (v[0]));
  svmdb_unmap (c);

  for (i = 0; i < vec_len (values); i++)
    vec_free (values[i]);
  vec_free (values);
}

static void
sigaction_handler (int signum, siginfo_t * i, void *notused)
{
  u32 action, opaque;

  action = (u32) (uword) i->si_ptr;
  action >>= 28;
  opaque = (u32) (uword) i->si_ptr;
  opaque &= ~(0xF0000000);

  clib_warning ("signal %d, action %d, opaque %x", signum, action, opaque);
}

static void
test_reg (char *chroot_path, u8 * vbl)
{
  svmdb_client_t *c;
  svmdb_notification_args_t args;
  svmdb_notification_args_t *a = &args;
  struct sigaction sa;
  svmdb_map_args_t *ma;

  ma = map_arg_setup (chroot_path);

  clib_memset (&sa, 0, sizeof (sa));
  sa.sa_sigaction = sigaction_handler;
  sa.sa_flags = SA_SIGINFO;
  if (sigaction (SIGUSR2, &sa, 0) < 0)
    {
      clib_unix_warning ("sigaction");
      return;
    }

  clib_memset (a, 0, sizeof (*a));

  c = svmdb_map (ma);

  a->add_del = 1 /* add */ ;
  a->nspace = SVMDB_NAMESPACE_STRING;
  a->var = (char *) vbl;
  a->elsize = 1;
  a->signum = SIGUSR2;
  a->action = SVMDB_ACTION_GET;
  a->opaque = 0x0eadbeef;

  svmdb_local_add_del_notification (c, a);

  (void) svmdb_local_get_string_variable (c, (char *) vbl);

  a->add_del = 0;		/* del */
  svmdb_local_add_del_notification (c, a);



  svmdb_unmap (c);
}

static void
unset_vec (char *chroot_path, u8 * vbl)
{
  svmdb_client_t *c;
  svmdb_map_args_t *ma;

  ma = map_arg_setup (chroot_path);

  c = svmdb_map (ma);

  svmdb_local_unset_vec_variable (c, (char *) vbl);
  svmdb_unmap (c);
}

static void
dump_vecs (char *chroot_path)
{
  svmdb_client_t *c;
  svmdb_map_args_t *ma;

  ma = map_arg_setup (chroot_path);

  c = svmdb_map (ma);

  svmdb_local_dump_vecs (c);
  svmdb_unmap (c);
}

static void
crash_test (char *chroot_path)
{
  svmdb_client_t *c;
  svmdb_map_args_t *ma;

  ma = map_arg_setup (chroot_path);

  c = svmdb_map (ma);

  clib_warning ("Grab region mutex and crash deliberately!");
  c->db_rp->mutex_owner_pid = getpid ();
  c->db_rp->mutex_owner_tag = -13;
  pthread_mutex_lock (&c->db_rp->mutex);

  abort ();
}

static void
map_with_size (char *chroot_path, uword size)
{
  svmdb_client_t *c;
  svmdb_map_args_t *ma;

  svmdbtool_main.size = size;
  ma = map_arg_setup (chroot_path);

  c = svmdb_map (ma);

  svmdb_unmap (c);
}

int
main (int argc, char **argv)
{
  unformat_input_t input;
  int parsed = 0;
  u8 *vbl = 0, *value = 0;
  char *chroot_path = 0;
  u8 *chroot_path_u8;
  u8 *filename;
  uword size;
  f64 vr;
  int uid, gid, rv;
  struct passwd _pw, *pw;
  struct group _grp, *grp;
  char *s, buf[128];

  svmdbtool_main.uid = geteuid ();
  svmdbtool_main.gid = getegid ();

  unformat_init_command_line (&input, argv);

  while (unformat_check_input (&input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (&input, "get-string %s", &vbl))
	{
	  get_string (chroot_path, vbl);
	  vec_free (vbl);
	  parsed++;
	}
      else if (unformat (&input, "set-string %s %s", &vbl, &value))
	{
	  set_string (chroot_path, vbl, value);
	  vec_free (vbl);
	  vec_free (value);
	  parsed++;
	}
      else if (unformat (&input, "unset-string %s", &vbl))
	{
	  unset_string (chroot_path, vbl);
	  vec_free (vbl);
	  parsed++;
	}
      else if (unformat (&input, "dump-strings"))
	{
	  dump_strings (chroot_path);
	  parsed++;
	}
      else if (unformat (&input, "unset-vec %s", &vbl))
	{
	  unset_vec (chroot_path, vbl);
	  vec_free (vbl);
	  parsed++;
	}
      else if (unformat (&input, "dump-vecs"))
	{
	  dump_vecs (chroot_path);
	  parsed++;
	}
      else if (unformat (&input, "test-vec %s", &vbl))
	{
	  test_vec (chroot_path, vbl);
	  // vec_free(vbl);
	  parsed++;
	}
      else if (unformat (&input, "vlib-vec-rate %f", &vr))
	{
	  test_vlib_vec_rate (chroot_path, vr);
	  parsed++;
	}
      else if (unformat (&input, "test-reg %s", &vbl))
	{
	  test_reg (chroot_path, vbl);
	  parsed++;
	}
      else if (unformat (&input, "crash-test"))
	{
	  crash_test (chroot_path);
	}
      else if (unformat (&input, "chroot %s", &chroot_path_u8))
	{
	  chroot_path = (char *) chroot_path_u8;
	}
      else if (unformat (&input, "fake-install %s", &value))
	{
	  fake_install (chroot_path, value);
	  parsed++;
	}
      else if (unformat (&input, "size %d", &size))
	{
	  map_with_size (chroot_path, size);
	  parsed++;
	}
      else if (unformat (&input, "uid %d", &uid))
	svmdbtool_main.uid = uid;
      else if (unformat (&input, "gid %d", &gid))
	svmdbtool_main.gid = gid;
      else if (unformat (&input, "uid %s", &s))
	{
	  /* lookup the username */
	  pw = NULL;
	  rv = getpwnam_r (s, &_pw, buf, sizeof (buf), &pw);
	  if (rv < 0)
	    {
	      fformat (stderr, "cannot fetch username %s", s);
	      exit (1);
	    }
	  if (pw == NULL)
	    {
	      fformat (stderr, "username %s does not exist", s);
	      exit (1);
	    }
	  vec_free (s);
	  svmdbtool_main.uid = pw->pw_uid;
	}
      else if (unformat (&input, "gid %s", &s))
	{
	  /* lookup the group name */
	  grp = NULL;
	  rv = getgrnam_r (s, &_grp, buf, sizeof (buf), &grp);
	  if (rv != 0)
	    {
	      fformat (stderr, "cannot fetch group %s", s);
	      exit (1);
	    }
	  if (grp == NULL)
	    {
	      fformat (stderr, "group %s does not exist", s);
	      exit (1);
	    }
	  vec_free (s);
	  svmdbtool_main.gid = grp->gr_gid;
	}
      else if (unformat (&input, "serialize-strings %s", &filename))
	{
	  vec_add1 (filename, 0);
	  serialize_strings (chroot_path, (char *) filename);
	  parsed++;
	}
      else if (unformat (&input, "unserialize-strings %s", &filename))
	{
	  vec_add1 (filename, 0);
	  unserialize_strings (chroot_path, (char *) filename);
	  parsed++;
	}
      else
	{
	  break;
	}
    }

  unformat_free (&input);

  if (!parsed)
    {
      fformat (stdout, "%s: get-string <name> | set-string <name> <value>\n",
	       argv[0]);
      fformat (stdout, "      unset-string <name> | dump-strings\n");
      fformat (stdout, "      test-vec <name> |\n");
      fformat (stdout, "      unset-vec <name> | dump-vecs\n");
      fformat (stdout, "      chroot <prefix> [uid <nnn-or-userid>]\n");
      fformat (stdout, "      [gid <nnn-or-group-name>]\n");
    }

  exit (0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
